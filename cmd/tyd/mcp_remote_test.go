package main

// The remote acceptance for `tyd mcp`: a real Control Panel, two real daemons
// that trust each other over a real transport, and the real MCP server driving
// the far one over a pipe.
//
// Everything below the MCP layer is real here, which is the point. The unit
// tests use a fake backend, and a fake backend cannot reach a pre-approval
// prompt, a write slot held by an attached person, or a certificate pin: those
// are properties of the daemon, not of the tool layer. What is still faked is
// the model. Nothing in this file decides anything on a model's behalf.
//
// Two things are deliberately not covered, and the PR says so rather than
// implying otherwise: an interactive CLI attach needs a TTY, and a password
// prompt has no echo state to observe.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/live"
	"tyd/internal/mcp"
	"tyd/internal/peers"
	"tyd/internal/protocol"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// remoteBudget is the ceiling for one scenario. Every wait in this file polls
// with a deadline under it, so a hung daemon fails the test instead of the run.
const remoteBudget = 60 * time.Second

// remoteShell is the shell every remote test asks for.
//
// Naming it keeps the prompt the model reads from depending on whichever shell
// the runner has as its default. /bin/sh is the choice because an interactive
// shell reads the operator's startup files, and those are the developer's to
// break: a ~/.bashrc that execs a shell which is not installed on this machine
// makes every bash session here exit at once, which is a fact about the machine
// and not about the code under test. sh reads no rc file, so the test cannot be
// decided by a dotfile.
const remoteShell = "/bin/sh"

// The daemon gives a live-agent five seconds to publish its socket, and the agent
// binds it only after its shell has started — a deliberate order, so a daemon that
// sees the socket can rely on the shell pid file. Under -race, where the agent is
// this same instrumented binary started once per iteration, that budget is
// sometimes not enough. So an open is retried, a bounded number of times and only
// for that one failure; anything else fails at once.
const (
	agentStartAttempts = 4
	agentStartWait     = 5 * time.Second
)

// remoteFixture is a paired client and server, each with its own state
// directory, reachable over a real transport.
type remoteFixture struct {
	opts    options // the client's options, which is what the MCP server uses
	key     ed25519.PrivateKey
	targets []mcpTarget
	ep      client.Endpoint
	srv     *server.Server
	// srvKey and srvSocket are the target's own identity and socket, which is
	// what an operator on that machine uses to approve a session.
	srvKey    ed25519.PrivateKey
	srvSocket string
}

// approve is `tyd session approve` on the target: the same unix socket, the same
// identity, the same route. Approving through the session manager instead would
// start the PTY and stop there, and the one-shot approval that lets the request
// through is recorded by the server on that route.
// approve is the create approval, which is not bound to a request: what it decides
// is "let this session exist". Requests waiting on it are decided separately.
func (f *remoteFixture) approve(t *testing.T, sessionID string) {
	t.Helper()
	ep := client.Endpoint{Kind: transport.KindUnix, Address: f.srvSocket}
	if _, err := client.Approve(ep, f.srvKey, sessionID, ""); err != nil {
		t.Fatalf("approve %s: %v", sessionID, err)
	}
}

// approveMatching approves the one waiting request whose description contains want,
// which is what an operator does after reading the list. An empty want approves
// only when there is exactly one, so a test cannot quietly approve a request it
// did not mean — the daemon refuses that case, and so does this.
func (f *remoteFixture) approveMatching(t *testing.T, sessionID, want string) {
	t.Helper()
	var hits []server.PendingApproval
	for _, p := range f.srv.PendingApprovals() {
		if p.SessionID == sessionID && (want == "" || strings.Contains(p.Request, want)) {
			hits = append(hits, p)
		}
	}
	switch len(hits) {
	case 0:
		t.Fatalf("approve %s: nothing waiting that matches %q", sessionID, want)
	case 1:
	default:
		var got []string
		for _, h := range hits {
			got = append(got, h.Request)
		}
		t.Fatalf("approve %s: %d requests match %q, so the test must say which: %v",
			sessionID, len(hits), want, got)
	}
	ep := client.Endpoint{Kind: transport.KindUnix, Address: f.srvSocket}
	if _, err := client.Approve(ep, f.srvKey, sessionID, hits[0].Digest); err != nil {
		t.Fatalf("approve %s (%s): %v", sessionID, hits[0].Request, err)
	}
}

// remoteShortDir returns a state directory short enough for a unix socket.
//
// t.TempDir() is under the test's own directory, and on macOS that path plus a
// socket name runs past the AF_UNIX limit. The daemon then fails to listen for a
// reason that has nothing to do with what is under test, so the directory is
// made under /tmp and cleaned up here.
func remoteShortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tyd")
	if err != nil {
		t.Fatalf("short state dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startRemote brings up a Control Panel, a target daemon on kind, and a client
// paired with it. The client options are ready to hand to the MCP server.
//
// kind is transport.KindTLS for the main path and transport.KindQUIC for the
// data-plane case. QUIC needs UDP, so the caller skips when it is unavailable.
func startRemote(t *testing.T, kind transport.Kind, approvalMode string) *remoteFixture {
	t.Helper()
	deadline := time.Now().Add(remoteBudget)

	svc := controlpanel.New()
	cpAddr, cpSrv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cpSrv.Close() })
	platform := "http://" + cpAddr.String()
	cp := cpclient.New(platform)

	srvDir := filepath.Join(remoteShortDir(t), "s")
	cliDir := filepath.Join(remoteShortDir(t), "c")
	for _, d := range []string{srvDir, cliDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	sKey, _, err := auth.EnsureIdentity(filepath.Join(srvDir, "id"), filepath.Join(srvDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	cKey, _, err := auth.EnsureIdentity(filepath.Join(cliDir, "id"), filepath.Join(cliDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	sPub := auth.EncodePublic(sKey.Public().(ed25519.PublicKey))
	cPub := auth.EncodePublic(cKey.Public().(ed25519.PublicKey))

	reg, err := cp.Register(sPub, approvalMode)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := cp.CreateInvite(reg.ID, sPub)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := cp.Accept(inv.Token, cPub, "box")
	if err != nil {
		t.Fatal(err)
	}

	// The target's own view of its peers, which is what its trust store is built
	// from. A real daemon gets this from the Control Panel on its first sync.
	remote, err := cp.ListPeers(reg.ID, sPub)
	if err != nil {
		t.Fatal(err)
	}
	sDoc := &peers.File{
		Platform: platform,
		Registration: &peers.Registration{
			ID: reg.ID, PublicKey: sPub, ApprovalMode: approvalMode, RegisteredAt: time.Now().UTC(),
		},
	}
	sDoc.MergePeers(cpPeersToLocal(remote))
	if err := peers.Save(filepath.Join(srvDir, "peers.json"), sDoc); err != nil {
		t.Fatal(err)
	}
	trust, err := auth.LoadStore(filepath.Join(srvDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sDoc.Peers {
		pub, err := auth.DecodePublic(p.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		trust.EnsurePeer(p.Nickname, pub, auth.AllGlobal)
	}

	// The data plane is the transport under test, so only that one is enabled.
	// A daemon with both would answer on whichever came first, and the test
	// would stop being a statement about the transport it names.
	// Every live-agent this fixture starts is killed at the end of the test.
	// An agent runs in its own session, so closing the server leaves it running:
	// that is what lets a session outlive a daemon restart in production, and it
	// means a test that does not kill them leaves a process per session behind.
	// Hundreds of them make the machine slow enough that the daemon's own
	// five-second budget for an agent socket starts to expire, which is a test
	// failing for a reason that has nothing to do with what it checks.
	liveRoot := filepath.Join(srvDir, "live")
	t.Cleanup(func() { killLiveAgents(liveRoot) })

	mgr := session.NewManager()
	// A session's shell lives in its own process, or it cannot be read after the
	// client that opened it goes away. A daemon starts one by re-executing
	// itself with __live-agent; TestMain makes this binary answer to that, so the
	// starter is the production one and only the binary differs.
	mgr.ConfigureLive(liveRoot, os.Args[0])
	mgr.SetStarter(testLiveStarter)

	cfg := server.Config{
		Socket:       filepath.Join(srvDir, "tyd.sock"),
		Listen:       "off",
		DataListen:   "off",
		CertPath:     filepath.Join(srvDir, "server.crt"),
		KeyPath:      filepath.Join(srvDir, "server.key"),
		Mgr:          mgr,
		Trust:        trust,
		ApprovalMode: approvalMode,
	}
	switch kind {
	case transport.KindQUIC:
		cfg.DataListen = "127.0.0.1:0"
	case transport.KindTLS:
		cfg.Listen = "127.0.0.1:0"
	default:
		t.Fatalf("fixture has no listener for %s", kind)
	}
	srv := server.NewWithConfig(cfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	addr, transportName := publishedAddr(t, srv, kind)
	fp := srv.TLSFingerprintFull()
	// The fixture binds loopback, so loopback is all it may publish.
	// transport.ExpandCandidates would add every interface address on the host,
	// and a client that prefers a non-loopback candidate would then dial an
	// address nothing is listening on. That would make the test a statement about
	// this machine's network rather than about the transport it names.
	cands := []string{addr}
	record := auth.NewEndpointRecord(reg.ID, sPub, addr, fp, transportName, cands,
		time.Now(), controlpanel.DefaultEndpointTTL, 1)
	sig, err := record.Sign(sKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.PublishEndpointFull(reg.ID, controlpanel.PublishEndpointRequest{
		PublicKey:  sPub,
		Addr:       addr,
		CertFP:     fp,
		Transport:  transportName,
		Candidates: cands,
		TTLSeconds: int(controlpanel.DefaultEndpointTTL / time.Second),
		Proof: &controlpanel.EndpointProof{
			Record: record,
			Sig:    auth.EncodeBytes(sig),
		},
	}); err != nil {
		t.Fatal(err)
	}

	// The client knows the target as an outbound peer, which is what --peer and
	// the target resolver read.
	cDoc := &peers.File{
		Platform: platform,
		Registration: &peers.Registration{
			ID: acc.SelfID, PublicKey: cPub, ApprovalMode: controlpanel.DefaultApproval, RegisteredAt: time.Now().UTC(),
		},
	}
	cDoc.UpsertPeer(peers.Peer{
		ID: acc.PeerID, PublicKey: acc.PeerPublicKey, Nickname: "box",
		Direction: "outbound", PairedAt: time.Now().UTC(),
	})

	opts := options{
		socket:     filepath.Join(cliDir, "tyd.sock"),
		identity:   filepath.Join(cliDir, "id"),
		trust:      filepath.Join(cliDir, "trusted.json"),
		peers:      filepath.Join(cliDir, "peers.json"),
		paired:     filepath.Join(cliDir, "paired.json"),
		recent:     filepath.Join(cliDir, "recent.json"),
		aliases:    filepath.Join(cliDir, "aliases.json"),
		sessions:   filepath.Join(cliDir, "sessions.json"),
		archive:    filepath.Join(cliDir, "archive.json"),
		platform:   platform,
		archiveTTL: DefaultArchiveTTL,
	}
	if err := peers.Save(opts.peers, cDoc); err != nil {
		t.Fatal(err)
	}
	targets := []mcpTarget{{label: "box", peerID: acc.PeerID, nickname: "box"}}

	ep := client.Endpoint{Kind: kind, Address: addr, CertFP: fp, Candidates: cands}
	if err := waitReady(ep, deadline); err != nil {
		t.Fatalf("target over %s never became ready: %v", kind, err)
	}
	return &remoteFixture{
		opts: opts, key: cKey, targets: targets, ep: ep, srv: srv,
		srvKey: sKey, srvSocket: cfg.Socket,
	}
}

// killLiveAgents ends every agent under a live root, then waits briefly for them
// to go: a shell that outlives its agent would keep the temp dir's removal from
// finishing and would still be running after the test is over.
func killLiveAgents(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		live.KillAgent(filepath.Join(root, e.Name()))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		alive := false
		for _, e := range entries {
			if e.IsDir() && live.Alive(filepath.Join(root, e.Name())) {
				alive = true
			}
		}
		if !alive {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// testLiveStarter starts a live-agent from this test binary.
//
// The default starter runs `<execPath> __live-agent --dir <dir>`, and in a test
// that executable is the test binary, which would run the whole suite instead of
// becoming an agent. The role is chosen by the environment, which is what
// TestMain reads, so the two variables are what make the child an agent.
//
// -test.run=^$ is belt and braces: if the environment did not arrive, the child
// runs no test rather than the suite.
func testLiveStarter(_, dir string) (*exec.Cmd, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "TYD_TEST_LIVE_AGENT=1", "TYD_TEST_LIVE_DIR="+dir)
	logf, err := os.OpenFile(live.LogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		return nil, err
	}
	_ = logf.Close()
	return cmd, nil
}

func publishedAddr(t *testing.T, srv *server.Server, kind transport.Kind) (string, string) {
	t.Helper()
	if kind == transport.KindQUIC {
		addr := srv.DataPlaneAddr()
		if addr == "" {
			t.Fatal("the daemon published no QUIC data-plane address")
		}
		return addr, "quic"
	}
	addr := srv.ListenAddr()
	if addr == "" {
		t.Fatal("the daemon published no TLS address")
	}
	return addr, "tls"
}

// waitReady polls until the target answers or the deadline passes. A fixed sleep
// would be either too short on a loaded runner or a waste on a fast one, and
// under -race it is the difference between a green run and a flake.
func waitReady(ep client.Endpoint, deadline time.Time) error {
	var last error
	for time.Now().Before(deadline) {
		if err := client.WaitReady(ep, time.Second); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("timeout")
	}
	return last
}

// eventually polls cond until it holds. Every wait in the remote tests goes
// through here, so one stuck step fails the test with a message instead of
// hanging the run.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(remoteBudget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", remoteBudget, what)
}

// TestRemoteSessionRoundTrip: the whole point of the server. A model on this
// machine opens a session on the other one, types into it, and reads what it
// printed, over a real transport with a real certificate pin.
func TestRemoteSessionRoundTrip(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	opened := mc.openSession(t, "build")
	if got := opened.result.Session; got != "build" {
		t.Fatalf("session = %q, want build", got)
	}
	// Every result names the machine it ran on, so a model serving several
	// targets can tell which one answered.
	if !strings.Contains(opened.text, "target=box") {
		t.Fatalf("the result does not name the target:\n%s", opened.text)
	}
	if !strings.Contains(opened.result.HumanAttach, "box") {
		t.Fatalf("human_attach = %q, want a command that reaches the peer", opened.result.HumanAttach)
	}

	sent := mc.call(t, "session_send", map[string]any{
		"session": "build", "data": "echo remote-ok-4711\n",
		"wait": map[string]any{"match": "remote-ok-4711"},
	})
	if !strings.Contains(sent.text, "remote-ok-4711") {
		t.Fatalf("the marker never came back:\n%s", sent.text)
	}
	if !strings.Contains(sent.text, "target=box") {
		t.Fatalf("the send result does not name the target:\n%s", sent.text)
	}
	if sent.result.Reason != "match" {
		t.Fatalf("reason = %q, want match", sent.result.Reason)
	}
}

// A person attached to the session owns the write slot, and a send into it must
// say so rather than interleave. The CLI needs a TTY to attach, so the client
// library takes the slot over a real connection instead: the daemon cannot tell
// the two apart, which is the property under test.
func TestRemoteSendIsRefusedWhileAPersonIsAttached(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "held")
	// A real connection, authenticated and attaching, held open for the test.
	holder := attachAndHold(t, fx)
	defer holder.Close()

	// The daemon marks the session attached asynchronously, so the refusal is
	// polled rather than assumed.
	var refusal string
	eventually(t, "the attach to take the write slot", func() bool {
		res := mc.tryCall(t, "session_send", map[string]any{"session": "held", "data": "echo nope\n"})
		if res.err != "" {
			refusal = res.text
			return true
		}
		return false
	})
	if !strings.Contains(refusal, "session in use") {
		t.Fatalf("the refusal must name the reason a person is attached:\n%s", refusal)
	}
	// It has to be actionable: the model is told how to get in, not just that it
	// is out.
	if !strings.Contains(refusal, "attach") {
		t.Fatalf("the refusal does not say what to do:\n%s", refusal)
	}

	// Once the person lets go, the same call works. A refusal that never lifted
	// would be a wedged session, not a taken slot.
	holder.Close()
	eventually(t, "the send to be accepted after the attach ended", func() bool {
		return mc.tryCall(t, "session_send", map[string]any{"session": "held", "data": "echo back-again\n"}).err == ""
	})
}

// The approval a pre-mode target grants is spent by the first request that needs
// it, and the daemon reviews every later one. This pins that, because it decides
// whether `tyd mcp` is usable against a pre daemon at all.
func TestRemotePreApprovalIsSpentByTheFirstRequest(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalPre)
	mc := startMCP(t, fx)

	opened := mc.call(t, "session_open", map[string]any{"name": "gated"})
	if opened.result.State != "pending" {
		t.Fatalf("state = %q, want pending on a pre target", opened.result.State)
	}

	// The alias is the handle a model has; the id is not in the result, and a
	// model would not have it either.
	ref := opened.result.Session
	if ref != "gated" {
		t.Fatalf("session = %q, want the alias the model was given", ref)
	}
	sid := sessionIDForAlias(t, fx, ref)

	// Nothing may be driven before a person decides.
	first := mc.tryCall(t, "session_send", map[string]any{"session": ref, "data": "echo gated\n"})
	if first.err == "" {
		t.Fatal("a send into an unapproved pre session must be refused")
	}
	if !strings.Contains(first.text, "tyd session approve "+sid) {
		t.Fatalf("the refusal must name the command that unblocks it:\n%s", first.text)
	}

	// What the operator runs on the target. This approves the create.
	fx.approve(t, sid)

	// Approving the create does **not** carry a send through. It used to: the
	// approval recorded for the attach that follows a create was keyed on the
	// session alone, so the first gated request of any kind spent it — here, a
	// send the operator was never shown. An approval is bound to one request, and
	// this is the assertion that says so.
	if res := mc.tryCall(t, "session_send", map[string]any{"session": ref, "data": "echo one\n"}); res.err == "" {
		t.Fatal("approving the create carried a send the operator was not shown")
	}
	fx.approveMatching(t, sid, "send 9 bytes")

	// Now the send has its own approval, and it goes through.
	if res := mc.tryCall(t, "session_send", map[string]any{"session": ref, "data": "echo one\n"}); res.err != "" {
		t.Fatalf("the request the operator approved must be accepted:\n%s", res.text)
	}

	// And one approval still buys exactly one request. This is the finding that
	// decides whether a pre target is practical, so it is asserted rather than
	// described.
	second := mc.tryCall(t, "session_send", map[string]any{"session": ref, "data": "echo two\n"})
	if second.err == "" {
		t.Fatal("a pre approval was expected to be one-shot, and the second send was accepted")
	}
	if !strings.Contains(second.text, "tyd session approve "+sid) {
		t.Fatalf("the second refusal must again name the command that unblocks it:\n%s", second.text)
	}
}

// sessionIDForAlias resolves what the operator has to approve. The model only
// ever holds the alias, so the id in that command is the test's to look up.
func sessionIDForAlias(t *testing.T, fx *remoteFixture, name string) string {
	t.Helper()
	adoc, err := alias.Load(fx.opts.aliases)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range adoc.Aliases {
		if e.Name == name {
			return e.SessionID
		}
	}
	t.Fatalf("no alias named %q", name)
	return ""
}

// An interrupt has to reach a command that is running, on the far machine, over
// the real transport. A daemon that ignored it would leave the model waiting on
// a prompt that never comes back.
func TestRemoteInterruptStopsARunningCommand(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "slow")
	// The marker proves the shell is back at a prompt afterwards, which is what
	// tells the interrupt did something rather than being swallowed.
	mc.tryCall(t, "session_send", map[string]any{"session": "slow", "data": "sleep 30\n"})

	res := mc.call(t, "session_interrupt", map[string]any{"session": "slow"})
	after := mc.call(t, "session_send", map[string]any{
		"session": "slow", "data": "echo alive-9931\n",
		"wait": map[string]any{"match": "alive-9931"},
	})
	if !strings.Contains(after.text, "alive-9931") {
		t.Fatalf("the shell did not answer after the interrupt (%s):\n%s", res.text, after.text)
	}
}

// A successful send has to reach the archive, not just the helper. The
// bookkeeping is one line in the backend and this is what proves it is called:
// without it a session a model is actively driving would drop out of the list
// after --archive-ttl, and nobody would look for it there.
func TestRemoteDrivingASessionKeepsItListed(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "kept")
	mc.call(t, "session_send", map[string]any{
		"session": "kept", "data": "echo kept-1180\n",
		"wait": map[string]any{"match": "kept-1180"},
	})

	// The session is not hidden, and it is not carrying an archive mark.
	arch := loadArchive(fx.opts)
	sid := sessionIDForAlias(t, fx, "kept")
	if arch.SessionArchived(sid) {
		t.Fatal("a session the model just drove must not be archived")
	}
	listed := mc.call(t, "session_list", map[string]any{})
	if !strings.Contains(listed.text, "kept") {
		t.Fatalf("a driven session must still be listed:\n%s", listed.text)
	}
}

// The whole reason a list stops probing a target that has asked for approval:
// the operator's approval is one-shot, and a list that kept probing would spend it
// on a probe instead of on what the model asked for. This is that sequence end to
// end — refused list, no more probes, approve once, and the model's own send
// going through on that one approval.
func TestRemoteOneApprovalIsSpentByTheModelNotByAList(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalPre)
	mc := startMCP(t, fx)

	// Two sessions, so a list has more than one row to get wrong.
	mc.openSession(t, "first")
	mc.openSession(t, "second")
	first := sessionIDForAlias(t, fx, "first")
	second := sessionIDForAlias(t, fx, "second")

	// The first list probes the first row, is refused by the gate, and says which
	// command unblocks it. The second row is not probed at all: the target has
	// asked once, and asking again is what spends the approval.
	listed := mc.tryCall(t, "session_list", map[string]any{})
	if listed.err != "" {
		t.Fatalf("a list reports a refused probe as a row, not as a failure: %s", listed.err)
	}
	// Which row gets probed is the catalog's order to decide, and the order is not
	// stable across runs, so the test follows whichever one it was rather than
	// assuming. The point is that exactly one was.
	probed := probedSessionID(listed.text)
	if probed == "" {
		t.Fatalf("no row reported a probe failure:\n%s", listed.text)
	}
	if probed != first && probed != second {
		t.Fatalf("probed session %s, which is not one of the two", probed)
	}
	if !strings.Contains(listed.text, "tyd session approve "+probed) {
		t.Fatalf("the probed row must name the command that unblocks it:\n%s", listed.text)
	}
	if !strings.Contains(listed.text, "would spend the operator") {
		t.Fatalf("the row after a refusal must say it was not probed:\n%s", listed.text)
	}
	if !strings.Contains(listed.text, "no probe on box") {
		t.Fatalf("the footer must name the target that stopped being probed:\n%s", listed.text)
	}
	// One probe, not one per row.
	if n := strings.Count(listed.text, "probe failed"); n != 1 {
		t.Fatalf("a list of 2 rows made %d probes, want 1", n)
	}

	// The operator approves the probe the list made — the one request that was
	// actually asked for, named out of the list the daemon holds.
	fx.approveMatching(t, probed, "read "+probed)

	// A list must not spend it. The target is remembered as gated, so its rows
	// come from the catalog and say so.
	after := mc.call(t, "session_list", map[string]any{})
	if strings.Contains(after.text, "probe failed") {
		t.Fatalf("a list probed a target that had already asked for approval:\n%s", after.text)
	}
	if !strings.Contains(after.text, "no probe on box") {
		t.Fatalf("the list must say it stopped probing the target:\n%s", after.text)
	}
	// Both rows are still there: a model that could not see them would open a
	// third session on a machine that already has two.
	for _, name := range []string{"first", "second"} {
		if !strings.Contains(after.text, name) {
			t.Fatalf("the gated target's rows must still be listed, %s missing:\n%s", name, after.text)
		}
	}

	// That approval is spent by the probe's own retry and by nothing else. The
	// model's read is a *different* request — the approval names the operation, not
	// just the session — so it needs an approval of its own, and gets refused until
	// it has one. This used to pass through on the probe's approval, which is the
	// defect: an operator shown "read abc123" was also paying for a read the model
	// chose afterwards.
	read := mc.tryCall(t, "session_read", map[string]any{
		"session": probed, "wait": map[string]any{"idle_ms": 400},
	})
	if read.err == "" {
		t.Fatal("the probe's approval was spent by a read the operator was not shown")
	}
	fx.approveMatching(t, probed, "read "+probed)
	if read := mc.tryCall(t, "session_read", map[string]any{
		"session": probed, "wait": map[string]any{"idle_ms": 400},
	}); read.err != "" {
		t.Fatalf("the read the operator approved was not accepted: %s", read.err)
	}

	// And it really was one-shot: the next gated request is refused, and says
	// which command unblocks it. This is the whole reason a list stops probing.
	again := mc.tryCall(t, "session_read", map[string]any{
		"session": probed, "wait": map[string]any{"idle_ms": 400},
	})
	if again.err == "" {
		t.Fatal("a pre approval was expected to be one-shot, and the second read was accepted")
	}
	if !strings.Contains(again.text, "tyd session approve "+probed) {
		t.Fatalf("the second refusal must name the command that unblocks it:\n%s", again.text)
	}
}

// probedSessionID pulls the session id out of a row that reported a probe
// failure, so a test can follow whichever row the catalog put first.
func probedSessionID(text string) string {
	const marker = "probe failed: "
	i := strings.Index(text, marker)
	if i < 0 {
		return ""
	}
	rest := text[i+len(marker):]
	end := strings.IndexAny(rest, " .\n")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// A send on a pre target needs two approvals to be worth anything, and that is
// worth knowing rather than leaving a model to discover. The write is one gated
// request and the read that would report its output is another, so the operator's
// single approval buys the keystrokes and the model still cannot see what they
// did. It is the honest reason to pair an agent with --approval full rather than
// pre.
func TestRemoteSendOnAPreTargetSpendsTheApprovalOnTheWriteAlone(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalPre)
	mc := startMCP(t, fx)

	mc.openSession(t, "gated")
	sid := sessionIDForAlias(t, fx, "gated")
	fx.approve(t, sid)
	// The write is refused, which is what records the request an approval answers.
	mc.tryCall(t, "session_send", map[string]any{"session": "gated", "data": "echo two-approvals\n"})
	fx.approveMatching(t, sid, "send 19 bytes")

	// The write goes through on that approval — the one the operator was shown,
	// named in the list, with its size.
	sent := mc.tryCall(t, "session_send", map[string]any{
		"session": "gated", "data": "echo two-approvals\n",
	})
	if !strings.Contains(sent.text, "the keystrokes landed") {
		t.Fatalf("the write should have been allowed:\n%s", sent.text)
	}
	// And the read that would report its output is a separate gated request, so
	// the model is told to read rather than shown an answer it cannot have.
	if !strings.Contains(sent.text, "read the session to see what they produced") {
		t.Fatalf("the result must say the output is behind another approval:\n%s", sent.text)
	}
	read := mc.tryCall(t, "session_read", map[string]any{
		"session": "gated", "wait": map[string]any{"idle_ms": 400},
	})
	if read.err == "" {
		t.Fatal("the read after the write must need its own approval, or the write was not the only gated request")
	}
}

func TestRemoteCloseEndsTheSession(t *testing.T) {
	requireShell(t)
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "done")
	mc.call(t, "session_close", map[string]any{"session": "done"})
	if res := mc.tryCall(t, "session_send", map[string]any{"session": "done", "data": "echo after\n"}); res.err == "" {
		t.Fatal("a closed session must not accept a send")
	}
}

// The data plane is QUIC in production, so the case above does not speak for it.
// A CI runner without UDP cannot run this, and says so rather than passing on
// the TLS path and calling the transport covered.
func TestRemoteRoundTripOverQUIC(t *testing.T) {
	requireShell(t)
	if !udpReachable(t) {
		t.Skip("no usable UDP loopback on this host, so QUIC cannot be exercised here")
	}
	fx := startRemote(t, transport.KindQUIC, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "quic")
	res := mc.call(t, "session_send", map[string]any{
		"session": "quic", "data": "echo quic-5501\n",
		"wait": map[string]any{"match": "quic-5501"},
	})
	if !strings.Contains(res.text, "quic-5501") {
		t.Fatalf("the marker never came back over QUIC:\n%s", res.text)
	}
	if !strings.Contains(res.text, "target=box") {
		t.Fatalf("the result does not name the target:\n%s", res.text)
	}
}

// udpReachable reports whether a UDP socket can be bound and talked to on
// loopback. A QUIC listener that cannot bind is a property of the host, not a
// failure of the code, so it skips with the reason rather than failing.
func udpReachable(t *testing.T) bool {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer func() { _ = pc.Close() }()
	addr := pc.LocalAddr().String()
	c, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("x")); err != nil {
		return false
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	_, _, err = pc.ReadFrom(buf)
	return err == nil
}

// requireShell skips when the shell these tests ask for is not one this host
// lists. The daemon refuses an unlisted shell on purpose, and its list is
// /etc/shells on the machine running the test, so a missing entry is the host's
// shape and not a defect here.
func requireShell(t *testing.T) {
	t.Helper()
	if !shellIsListed(remoteShell) {
		t.Skipf("%s is not listed in /etc/shells on this host, and the daemon refuses an unlisted "+
			"shell on purpose; these tests ask for %s to keep their prompt and matches stable",
			remoteShell, remoteShell)
	}
}

func shellIsListed(want string) bool {
	b, err := os.ReadFile("/etc/shells")
	if err != nil {
		// Without the file the daemon exempts every shell, so the test may run.
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == want {
			return true
		}
	}
	return false
}

// attachAndHold takes the exclusive write slot over a real connection, the way
// an attached person does, and keeps it until the returned conn is closed.
//
// The frames are pumped by a goroutine so a daemon that never answers leaves the
// poll to time out rather than blocking a read for the whole budget.
func attachAndHold(t *testing.T, fx *remoteFixture) *client.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), remoteBudget)
	t.Cleanup(cancel)
	c, err := client.DialContext(ctx, fx.ep, fx.key)
	if err != nil {
		t.Fatalf("dial for the attach: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	sid := firstCatalogSession(t, fx)
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: sid, Rows: 24, Cols: 80}); err != nil {
		t.Fatalf("attach frame: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(remoteBudget))

	frames := make(chan protocol.Frame, 64)
	go func() {
		defer close(frames)
		for {
			frame, err := c.Recv()
			if err != nil {
				return
			}
			select {
			case frames <- frame:
			default:
			}
		}
	}()

	// The daemon acknowledges the attach before it streams. Waiting for that
	// frame is what makes the slot genuinely taken rather than merely requested.
	eventually(t, "the attach to be accepted", func() bool {
		for {
			select {
			case frame, ok := <-frames:
				if !ok {
					return false
				}
				if frame.Type == protocol.TypeAttached {
					return true
				}
				if frame.Type == protocol.TypeError {
					return false
				}
			default:
				return false
			}
		}
	})
	return c
}

func firstCatalogSession(t *testing.T, fx *remoteFixture) string {
	t.Helper()
	cat := loadLocalCatalog(fx.opts)
	for _, rec := range cat.List() {
		return rec.ID
	}
	t.Fatal("the client catalog holds no session to attach to")
	return ""
}

// mcpClient speaks the protocol over a pipe, so the test drives the real stdio
// server rather than its internals.
//
// The reader runs in its own goroutine. A pipe is unbuffered, so a client that
// wrote a request before reading would deadlock against a progress notification
// the server was in the middle of writing: neither side would be reading.
type mcpClient struct {
	t   *testing.T
	log *lockedBuffer
	in  *io.PipeWriter
	enc *json.Encoder
	ans chan rpcResponse

	mu   sync.Mutex
	next int
}

// lockedBuffer collects the server's stderr so a failed call can show it. The
// server writes from its own goroutine while the test reads, so the buffer needs
// its own lock; a plain strings.Builder races and the race detector is right to
// say so.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// startMCP runs the real server over a pipe and returns a client for it.
func startMCP(t *testing.T, fx *remoteFixture) *mcpClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverIn, clientToServer := io.Pipe()
	clientIn, serverOut := io.Pipe()

	errBuf := &lockedBuffer{}
	done := make(chan error, 1)
	go func() {
		err := mcp.Serve(ctx, serverIn, serverOut,
			newMCPBackend(fx.opts, fx.key, fx.targets), errBuf, mcp.Options{
				MaxSessions: 4,
				Peers:       mcpPeerLabels(fx.targets),
			})
		_ = serverIn.Close()
		_ = serverOut.Close()
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("the MCP server did not stop; stderr: %s", errBuf.String())
		}
	})

	mc := &mcpClient{
		t:   t,
		log: errBuf,
		in:  clientToServer,
		enc: json.NewEncoder(clientToServer),
		ans: make(chan rpcResponse, 64),
	}
	// Serve checks its context between frames, and the frame it is waiting for is
	// a read that a cancelled context cannot interrupt. Closing this end is what
	// a client does when it goes away, and it is what gives the server its EOF.
	t.Cleanup(func() { _ = mc.in.Close() })
	go func() {
		defer close(mc.ans)
		dec := json.NewDecoder(clientIn)
		for {
			var resp rpcResponse
			if err := dec.Decode(&resp); err != nil {
				return
			}
			mc.ans <- resp
		}
	}()
	mc.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"clientInfo":      map[string]any{"name": "remote-test", "version": "1"},
		"capabilities":    map[string]any{},
	})
	return mc
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// toolResult is the structured content a tool call answers with: the fields this
// file reads, which are the ones a model is meant to act on. The type in the mcp
// package is unexported, so the fields are read here rather than by widening
// that package for a test.
type toolResult struct {
	Session     string `json:"session"`
	Peer        string `json:"peer"`
	HumanAttach string `json:"human_attach"`
	SessionID   string `json:"id"`
	State       string `json:"session_state"`
	Reason      string `json:"reason"`
}

type toolCall struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StructuredContent toolResult `json:"structuredContent"`
	IsError           bool       `json:"isError"`
}

type toolOutcome struct {
	text   string
	result toolResult
	isErr  bool
	err    string
}

// openSession opens a session, retrying only the one failure that is about this
// machine rather than about the code.
//
// The daemon gives a live-agent five seconds to publish its socket, and the agent
// binds that socket only after its shell has started — a deliberate order, so a
// daemon that sees the socket can rely on the shell pid file. So the budget has
// to cover forking an agent and running a login shell inside it, and under
// -race, where the agent is this same instrumented binary started once per
// iteration, five seconds is sometimes not enough. Retrying the open keeps the
// assertion about the tools rather than about that budget, and it retries
// nothing else: a failure with any other cause fails the test at once.
func (mc *mcpClient) openSession(t *testing.T, name string) toolOutcome {
	t.Helper()
	var out toolOutcome
	for attempt := 0; attempt < agentStartAttempts; attempt++ {
		// tryCall, not call: a failure here is the thing being retried, and call
		// would end the test before the loop could look at it.
		out = mc.tryCall(t, "session_open", map[string]any{"name": name, "shell": remoteShell})
		if out.err == "" {
			return out
		}
		if !strings.Contains(out.text, "wait agent sock") {
			t.Fatalf("session_open %q failed for a reason that is not the agent's start-up budget: %s", name, out.err)
		}
		if attempt == agentStartAttempts-1 {
			break
		}
		// Logged, because a retry that quietly papers over a slow machine is how
		// a real failure starts being ignored.
		t.Logf("session_open %q: the live-agent socket did not appear in %s, retrying (attempt %d of %d)",
			name, agentStartWait, attempt+1, agentStartAttempts)
		// The previous iteration's agent is still tearing down; give the machine
		// a moment before starting another.
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("session_open %q did not get a live-agent socket in %d attempts: %s",
		name, agentStartAttempts, out.text)
	return out
}

// call runs a tool and fails the test if the call itself was refused. A tool
// that reports a failure answers with isError, not a protocol error, so this
// only catches a broken call.
func (c *mcpClient) call(t *testing.T, name string, args map[string]any) toolOutcome {
	t.Helper()
	out := c.tryCall(t, name, args)
	if out.err != "" {
		t.Fatalf("%s failed: %s\nmcp stderr:\n%s", name, out.err, c.log.String())
	}
	return out
}

// tryCall runs a tool and reports whatever came back, including a refusal.
func (c *mcpClient) tryCall(t *testing.T, name string, args map[string]any) toolOutcome {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	raw := c.request("tools/call", map[string]any{"name": name, "arguments": args})
	var call toolCall
	if err := json.Unmarshal(raw, &call); err != nil {
		t.Fatalf("%s: unreadable result: %v (%s)", name, err, raw)
	}
	out := toolOutcome{result: call.StructuredContent, isErr: call.IsError}
	for _, part := range call.Content {
		if part.Type == "text" {
			out.text += part.Text
		}
	}
	if call.IsError {
		out.err = out.text
	}
	return out
}

// request writes one call and returns its result. Frames without the matching id
// are notifications and are skipped.
func (c *mcpClient) request(method string, params map[string]any) json.RawMessage {
	c.t.Helper()
	c.mu.Lock()
	c.next++
	id := c.next
	c.mu.Unlock()

	if err := c.enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	}); err != nil {
		c.t.Fatalf("write %s: %v", method, err)
	}

	timeout := time.After(remoteBudget)
	for {
		select {
		case resp, ok := <-c.ans:
			if !ok {
				c.t.Fatalf("the server closed the connection while %s was in flight", method)
			}
			if len(resp.ID) == 0 {
				continue
			}
			var got int
			if err := json.Unmarshal(resp.ID, &got); err != nil || got != id {
				continue
			}
			if resp.Error != nil {
				c.t.Fatalf("%s: protocol error %d: %s", method, resp.Error.Code, resp.Error.Message)
			}
			return resp.Result
		case <-timeout:
			c.t.Fatalf("no answer to %s within %s", method, remoteBudget)
		}
	}
}

// A secret write to a remote target crosses two hops: this daemon to the target's
// daemon, and the target's daemon to the agent holding the PTY. A proxy that
// dropped the flag would turn a refusal into a silent write in the clear, which is
// the failure the whole feature exists to prevent — and it would look like the
// feature working, because the write succeeds.
func TestTheSecretFlagSurvivesBothHops(t *testing.T) {
	fx := startRemote(t, transport.KindTLS, controlpanel.ApprovalFull)
	mc := startMCP(t, fx)

	mc.openSession(t, "gated")
	// A read first, so the model has seen the prompt — and, on the way, learned
	// what build the far agent is.
	mc.call(t, "session_read", map[string]any{
		"session": "gated", "wait": map[string]any{"idle_ms": 300},
	})

	// An ordinary prompt echoes, so this is the refusal that means "these bytes
	// would be recorded". It can only arrive if the flag reached the agent.
	out := mc.tryCall(t, "session_send", map[string]any{
		"session": "gated", "data": "echo should-not-land\n", "secret": true,
	})
	if out.err == "" {
		t.Fatal("a secret write was accepted through both hops")
	}
	// Which of the three refusals comes back depends on the line discipline of the
	// target's terminal at that instant, which is the thing the feature measures
	// rather than controls. What must be true is that the refusal came from the
	// agent's own check, so all three are accepted and the version gate is not:
	// the version gate firing would mean the flag never arrived.
	fromAgent := false
	for _, phrase := range []string{"the terminal is echoing", "in raw mode", "could not be read"} {
		if strings.Contains(out.text, phrase) {
			fromAgent = true
			t.Logf("refused by the agent's check: %s", phrase)
		}
	}
	if strings.Contains(out.text, "has not said what build it is") {
		t.Fatalf("the version gate fired, so the flag never reached the agent: %s", out.text)
	}
	if !fromAgent {
		t.Fatalf("the refusal did not come from the agent's echo check: %s", out.text)
	}

	// And the shell must not have received it.
	after := mc.call(t, "session_read", map[string]any{
		"session": "gated", "wait": map[string]any{"idle_ms": 300},
	})
	if strings.Contains(after.text, "should-not-land") {
		t.Fatalf("the refused bytes reached the shell:\n%s", after.text)
	}
}
