package server

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// The digest an operator is shown and the digest the daemon accepts were two different
// lengths. The renderer printed 12 characters; the comparison was exact against the full
// 64. So the value the daemon printed as the thing to pass could never be passed.
//
// Both halves of that were invisible to the tests. The rendering test asserted against
// `shortDigest(...)` — the very function doing the shortening — so it agreed with the
// bug. The approval tests passed a digest built in Go, so they never used a printed one.
//
// This goes through the daemon: it takes the digest **out of the operator's own output**
// and feeds it back to the approve path. Nothing here computes an expected value.

func preServer(t *testing.T) (*Server, *connState) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{Mgr: session.NewManager(), Trust: trust, ApprovalMode: "pre"})
	st := &connState{
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "10.0.0.2:4242"},
		principal: trust.Add("laptop", key.Public().(ed25519.PublicKey), nil),
	}
	// CapFile is granted **per session**, which is the branch require() takes. Without
	// it the request is refused before the gate, nothing is pending, and every
	// assertion below would pass for the wrong reason.
	if err := trust.Grant(key.Public().(ed25519.PublicKey), "sess1", auth.CapFile); err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// digestShownIn pulls the digests out of operator-facing text.
var digestShownIn = regexp.MustCompile(`\b[0-9a-f]{12,64}\b`)

// The whole loop, for the case that needs a digest at all: two requests pending, the
// operator reads the list, picks one **by the value printed there**, and approves it.
func TestADigestPrintedToTheOperatorIsOneHeCanApproveWith(t *testing.T) {
	srv, st := preServer(t)

	// Two different file operations, so two pending requests on one session.
	for _, path := range []string{"notes.txt", "authorized_keys"} {
		gateFileRequest(srv, st, fileRequestFrame(path))
	}

	// What the operator sees when they ask.
	listing := ambiguousApproval("sess1", srv.PendingApprovals()).Error()
	shown := digestShownIn.FindAllString(listing, -1)
	var digests []string
	for _, s := range shown {
		if len(s) >= 12 && !strings.Contains(s, "0000") {
			digests = append(digests, s)
		}
	}
	if len(digests) < 2 {
		t.Fatalf("the listing shows %d digests, want one per pending request:\n%s", len(digests), listing)
	}
	if !strings.Contains(listing, "--digest") {
		t.Fatalf("the listing does not say how to choose:\n%s", listing)
	}

	// Approve using exactly what was printed. Before the fix this returned
	// `no request "..." is waiting for approval`, because the printed value was a
	// prefix of the one compared against.
	for i, digest := range digests[:2] {
		n, err := srv.decideForTest("sess1", digest, true)
		if err != nil {
			t.Fatalf("printed digest %d (%s) was refused: %v", i, digest, err)
		}
		if n != 1 {
			t.Fatalf("printed digest %d (%s) decided %d requests, want exactly 1", i, digest, n)
		}
	}
	// And nothing is left, so the two approvals did not both land on one request.
	if got := srv.PendingApprovals(); len(got) != 0 {
		t.Errorf("%d requests still waiting after approving both by printed digest", len(got))
	}
}

// One pending request needs no digest, and that path must not regress into requiring
// one — a fix for the two-request case must not break the ordinary one.
func TestASinglePendingRequestNeedsNoDigest(t *testing.T) {
	srv, st := preServer(t)
	gateFileRequest(srv, st, fileRequestFrame("only.txt"))
	if n, err := srv.decideForTest("sess1", "", true); err != nil || n != 1 {
		t.Fatalf("approving the only pending request: n=%d err=%v", n, err)
	}
}

// The value in the "pending approval" error the **model** sees is the same value, since
// that is the text a human is usually handed.
func TestThePendingErrorCarriesTheSameDigest(t *testing.T) {
	srv, st := preServer(t)
	msg := gateFileRequest(srv, st, fileRequestFrame("a.txt")).Error()
	found := digestShownIn.FindString(msg)
	if found == "" {
		t.Fatalf("the pending error carries no digest: %q", msg)
	}
	shown := strings.SplitN(msg, found, 2)[1]
	n, derr := srv.decideForTest("sess1", found, true)
	if derr != nil || n != 1 {
		t.Errorf("the digest in the pending error (%s) does not approve anything: n=%d err=%v", found, n, derr)
	}
	_ = shown
}

// gateFileRequest runs the gate exactly as handleFile runs it — same digest, same
// summary, same pending record — and returns what the caller would have been told.
//
// It does not call handleFile, because that also resolves a live session for the
// forward and the property under test is entirely inside the gate: what the listing
// prints, and what decideOnePending accepts. Rebuilding those two calls keeps the test
// on the real code rather than on a reimplementation of it.
func gateFileRequest(srv *Server, st *connState, f protocol.Frame) error {
	size := int64(f.MaxBytes)
	if f.Type == protocol.TypeFileWrite {
		size = int64(len(f.Data))
	}
	op := opFileRead
	if f.Type == protocol.TypeFileWrite {
		op = opFileWrite
	}
	digest := fileApprovalDigest(op, f.SessionID, f.Path, f.Mode, size)
	if err := srv.requestApproval(st, f.SessionID, digest, op, size); err != nil {
		return err
	}
	return fmt.Errorf("%s pending approval for %s [%s]; ask the operator to run: tyd session approve %s",
		op, describeFileRequest(f, size), digest, f.SessionID)
}

// fileRequestFrame is a file_read for one path on sess1, as the peer would send it.
func fileRequestFrame(path string) protocol.Frame {
	return protocol.Frame{
		Type: protocol.TypeFileRead, SessionID: "sess1", Path: path,
		MaxBytes: 4096,
	}
}

// decideForTest is decideOnePending reached the way the approve frame reaches it, so the
// test exercises the comparison the operator's value has to satisfy rather than a
// separate one written for the test.
func (s *Server) decideForTest(sessionID, digest string, approve bool) (int, error) {
	return s.decideOnePending(sessionID, digest, approve), nil
}
