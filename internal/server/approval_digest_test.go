package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/transport"
)

// An approval is bound to one request. These are the properties that binding is
// for, and each of them is a way the previous session-only binding went wrong.

// gated is a pre-mode server with one session, and the tools to drive it.
func gatedServer(t *testing.T) (*Server, *connState) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{Mgr: nil, Trust: trust, ApprovalMode: "pre", ApprovalTTL: 10 * time.Minute})
	srv.pending = make(map[string]*pendingAttach)
	srv.approved = make(map[string]approval)
	// pre mode, and a transport that is not the local socket — the gate applies to
	// a peer, which is where an approval is somebody else's decision.
	st := &connState{
		principal: &auth.Principal{Name: "alice", Pub: key.Public().(ed25519.PublicKey)},
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "203.0.113.9:41234"},
	}
	return srv, st
}

func TestAnApprovalForOneRequestIsNotSpentByAnother(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"

	// The operator approves a read.
	if err := srv.gateAttach(st, sid, opRead, 0); err == nil {
		t.Fatal("the first request should have asked for approval")
	}
	readDigest := approvalDigest(opRead, sid, 0)
	srv.approveOne(sid, readDigest)

	// A send is a different request and must not ride on it.
	if err := srv.gateAttach(st, sid, opSend, 9); err == nil {
		t.Error("an approval for a read let a send through")
	}

	// And a read of the same session is: that is the one it was granted for.
	if err := srv.gateAttach(st, sid, opRead, 0); err != nil {
		t.Errorf("the request the approval was for was refused: %v", err)
	}
}

func TestAnApprovalDoesNotCarryAcrossSize(t *testing.T) {
	// The digest carries the byte count, so an approval for one send is not an
	// approval for a different send. Not content binding — a same-length payload
	// still matches, and the docs say so — but a different length is a different
	// request, and the operator was shown the length.
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opSend, 9)
	srv.approveOne(sid, approvalDigest(opSend, sid, 9))
	if err := srv.gateAttach(st, sid, opSend, 40); err == nil {
		t.Error("an approval for a 9 byte send let a 40 byte send through")
	}
	if err := srv.gateAttach(st, sid, opSend, 9); err != nil {
		t.Errorf("the 9 byte send the approval was for was refused: %v", err)
	}
}

func TestTheApprovalIsOneShot(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	digest := approvalDigest(opRead, sid, 0)
	srv.approveOne(sid, digest)
	if err := srv.gateAttach(st, sid, opRead, 0); err != nil {
		t.Fatalf("the first use was refused: %v", err)
	}
	if err := srv.gateAttach(st, sid, opRead, 0); err == nil {
		t.Error("one approval covered two requests")
	}
}

func TestAnExpiredApprovalIsNotSpent(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	digest := approvalDigest(opRead, sid, 0)
	srv.approveOne(sid, digest)
	srv.mu.Lock()
	key := approvalKey(sid, gatePub(st.principal), digest)
	srv.approved[key] = approval{expires: time.Now().Add(-time.Second), digest: digest}
	srv.mu.Unlock()
	if err := srv.gateAttach(st, sid, opRead, 0); err == nil {
		t.Error("an expired approval was spent")
	}
}

func TestIdenticalRequestsShareOnePending(t *testing.T) {
	// A model retrying must not fill the operator's list with copies of one
	// request. Same digest, same record — and the count the cap sees is one.
	srv, st := gatedServer(t)
	const sid = "sess1"
	for i := 0; i < 5; i++ {
		_ = srv.gateAttach(st, sid, opRead, 0)
	}
	if n := len(srv.PendingApprovals()); n != 1 {
		t.Errorf("five identical requests produced %d pending records, want 1", n)
	}
}

func TestDifferentRequestsDoNotShareAPending(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	_ = srv.gateAttach(st, sid, opSend, 9)
	if n := len(srv.PendingApprovals()); n != 2 {
		t.Errorf("a read and a send produced %d pending records, want 2", n)
	}
}

func TestThePendingListIsBounded(t *testing.T) {
	// A peer must not be able to bury an operator. Distinct requests count; the
	// cap refuses rather than dropping an arbitrary one, so the approvals a person
	// was going to look at survive.
	srv, st := gatedServer(t)
	const sid = "sess1"
	// Every unapproved request is refused; the question is whether the ones past
	// the cap say why. A peer that could pile requests onto the list without
	// hitting a limit would bury the ones a person was going to look at.
	var capped int
	for i := 0; i < pendingCap+8; i++ {
		err := srv.gateAttach(st, sid, opSend, int64(i))
		if err != nil && strings.Contains(err.Error(), "already has") {
			capped++
		}
	}
	if capped == 0 {
		t.Fatalf("nothing was refused by the cap, so it is not in the path")
	}
	if n := len(srv.PendingApprovals()); n > pendingCap {
		t.Errorf("%d pending records, above the cap of %d", n, pendingCap)
	}
}

func TestTheOperatorIsShownWhatIsBeingApproved(t *testing.T) {
	// Bind exactly what the operator can see: the operation and its size. Content
	// is never in the pending record, the stderr line or the listing, because a
	// digest over a low-entropy secret is a dictionary verifier and the pending
	// record is readable.
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opSend, 9)
	got := srv.PendingApprovals()
	if len(got) != 1 {
		t.Fatalf("%d pending", len(got))
	}
	p := got[0]
	if p.Op != opSend || p.Size != 9 {
		t.Errorf("listing says op=%q size=%d, want send/9", p.Op, p.Size)
	}
	if !strings.Contains(p.Request, "9 bytes") {
		t.Errorf("the description does not carry the size: %q", p.Request)
	}
	if p.Digest == "" || p.Digest == strings.Repeat("0", 64) {
		t.Errorf("no usable digest in the listing: %q", p.Digest)
	}
	// The digest is over metadata, so the same size and session give the same one,
	// and no field of it can be read back as content.
	if approvalDigest(opSend, sid, 9) != approvalDigest(opSend, sid, 9) {
		t.Error("the digest is not stable")
	}
	if approvalDigest(opSend, sid, 9) == approvalDigest(opSend, sid, 10) {
		t.Error("the digest does not distinguish sizes")
	}
}

func TestAmbiguityIsRefusedWithTheList(t *testing.T) {
	// Two requests waiting and nobody said which. Approving both would decide a
	// request the operator was never shown, which is the defect itself.
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	_ = srv.gateAttach(st, sid, opSend, 9)

	waiting := srv.pendingFor(sid)
	if len(waiting) != 2 {
		t.Fatalf("%d waiting", len(waiting))
	}
	err := ambiguousApproval(sid, waiting)
	for _, want := range []string{"2 requests", approvalDigest(opRead, sid, 0), "--digest"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

func TestApprovingOneOfSeveralLeavesTheOther(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	_ = srv.gateAttach(st, sid, opSend, 9)

	readDigest := approvalDigest(opRead, sid, 0)
	if n := srv.decideOnePending(sid, readDigest, true); n != 1 {
		t.Fatalf("decided %d, want 1", n)
	}
	if n := len(srv.PendingApprovals()); n != 1 {
		t.Errorf("%d still waiting, want the send", n)
	}
	// The approved read goes; the send still does not.
	if err := srv.gateAttach(st, sid, opRead, 0); err != nil {
		t.Errorf("the approved read was refused: %v", err)
	}
	if err := srv.gateAttach(st, sid, opSend, 9); err == nil {
		t.Error("the send went through on the read's approval")
	}
}

func TestConcurrentApprovalsStillSpendOne(t *testing.T) {
	// Same shape as the probe slot in #121: several callers, one approval, and the
	// count is on the thing being spent rather than on a log line.
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)
	digest := approvalDigest(opRead, sid, 0)
	srv.approveOne(sid, digest)

	var wg sync.WaitGroup
	var allowed int
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each caller needs its own connState; they share the principal.
			if err := srv.gateAttach(st, sid, opRead, 0); err == nil {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Errorf("%d of 8 concurrent requests were allowed, want 1", allowed)
	}
}

// approveOne is the operator's decision, as decideOnePending sees it.
func (s *Server) approveOne(sessionID, digest string) {
	s.decideOnePending(sessionID, digest, true)
}

// A pending record is readable by the operator and `pre` mode prints a line to
// stderr, so a digest taken over a `send`'s content would be an offline dictionary
// verifier for anything low-entropy. The content must not be recoverable from
// anything the gate touches.
func TestTheGateNeverCarriesSendContent(t *testing.T) {
	const canary = "correct-horse-battery-staple-9f3a"
	srv, st := gatedServer(t)
	const sid = "sess1"

	line := captureStderr(t, func() {
		_ = srv.gateAttach(st, sid, opSend, int64(len(canary)))
	})

	// The record, the description the operator reads, the listing, and the line on
	// stderr. Nothing may contain the content, and nothing may contain a digest
	// that could be checked against a guess.
	pending := srv.PendingApprovals()
	if len(pending) != 1 {
		t.Fatalf("%d pending", len(pending))
	}
	for where, text := range map[string]string{
		"stderr line":     line,
		"listing":         pending[0].Request,
		"digest":          pending[0].Digest,
		"approval record": srv.approvedRecordForTest(sid, pending[0].Digest),
	} {
		if strings.Contains(text, canary) {
			t.Errorf("the %s carries the content:\n%s", where, text)
		}
	}
	if strings.Contains(line, "correct-horse") {
		t.Errorf("the stderr line echoes the payload:\n%s", line)
	}
	// What the operator is told is the size, which is not the content.
	if !strings.Contains(line, fmt.Sprintf("%d bytes", len(canary))) {
		t.Errorf("the line does not report the size it is approving:\n%s", line)
	}
}

// An approving client that does not say which version it is may be a build from
// before approvals were bound to a request. Refusing it is the point: falling back
// to "approve whatever is pending" would leave the defect in place for exactly the
// deployments that have not upgraded, which are the ones least able to notice.
func TestAnApprovingClientWithNoVersionIsRefused(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"
	_ = srv.gateAttach(st, sid, opRead, 0)

	// What the handler does with a frame that carries no version.
	err := srv.checkApproverVersion(0)
	if err == nil {
		t.Fatal("a version-less approving client was accepted")
	}
	for _, want := range []string{"upgrade the client", "version 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if err := srv.checkApproverVersion(auth.CurrentVersion); err != nil {
		t.Errorf("a current approving client was refused: %v", err)
	}
}

// captureStderr is captureStdout for the other stream: the approval line goes to
// stderr, and that is the surface a person reads.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

// A cap that can be reached permanently, by the party it is meant to slow down, is
// a denial of service with a fuse that never burns down. Expiry used to happen only
// where expired entries are *read*, and in production that is `tyd session approve`
// — so a principal that filled its slots and was never approved kept them, and
// every later request was refused for good.
func TestAnExpiredPendingDoesNotHoldASlotForever(t *testing.T) {
	srv, st := gatedServer(t)
	const sid = "sess1"

	// Fill it.
	for i := 0; i < pendingCap; i++ {
		_ = srv.gateAttach(st, sid, opSend, int64(i))
	}
	if err := srv.gateAttach(st, sid, opSend, 999); err == nil ||
		!strings.Contains(err.Error(), "already has") {
		t.Fatalf("the cap did not engage: %v", err)
	}

	// Wait out the TTL without anybody listing or deciding anything — the state a
	// daemon sits in when no operator is looking.
	srv.mu.Lock()
	for _, req := range srv.pending {
		req.at = time.Now().Add(-2 * srv.cfg.ApprovalTTL)
	}
	srv.mu.Unlock()

	// The slots must be free again without anything having cleaned them.
	if err := srv.gateAttach(st, sid, opSend, 1001); err == nil {
		t.Fatal("a request was refused by slots that had expired")
	}
	if err := srv.gateAttach(st, sid, opSend, 1002); err == nil {
		t.Fatal("a second request was refused by slots that had expired")
	}
	// And the expired records are actually gone, not merely uncounted.
	srv.mu.Lock()
	left := len(srv.pending)
	srv.mu.Unlock()
	if left != 2 {
		t.Errorf("%d pending records left after expiry, want 2", left)
	}
}

func TestTheCapMessageSaysWhoseBudgetItIs(t *testing.T) {
	// A peer that hit the limit needs to know the waiting requests are its own and
	// that a person has to act. "Too many" on its own reads as the daemon being busy.
	srv, st := gatedServer(t)
	const sid = "sess1"
	for i := 0; i <= pendingCap; i++ {
		_ = srv.gateAttach(st, sid, opSend, int64(i))
	}
	err := srv.gateAttach(st, sid, opSend, 4242)
	if err == nil {
		t.Fatal("expected the cap to refuse")
	}
	for _, want := range []string{"from you", "expire after", "tyd session approve " + sid} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}
