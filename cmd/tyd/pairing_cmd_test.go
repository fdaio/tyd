package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
)

func TestPrintAcceptResult(t *testing.T) {
	acc := &controlpanel.AcceptResponse{PeerID: "peer1", PeerNickname: "laptop"}
	var errBuf, outBuf bytes.Buffer
	printAcceptResult(&errBuf, &outBuf, acc, true)
	if !strings.Contains(errBuf.String(), "paired with peer1") || strings.Contains(errBuf.String(), "already paired") {
		t.Fatalf("fresh: %q", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "tyd session create --peer laptop") {
		t.Fatalf("fresh hint: %q", errBuf.String())
	}
	if strings.TrimSpace(outBuf.String()) != "peer1" {
		t.Fatalf("stdout %q", outBuf.String())
	}

	errBuf.Reset()
	outBuf.Reset()
	printAcceptResult(&errBuf, &outBuf, acc, false)
	if strings.Contains(errBuf.String(), "session create") {
		t.Fatalf("offline hint: %q", errBuf.String())
	}

	errBuf.Reset()
	acc.AlreadyPaired = true
	printAcceptResult(&errBuf, &outBuf, acc, true)
	got := errBuf.String()
	if !strings.Contains(got, "already paired with peer1 (laptop)") || !strings.Contains(got, "tyd session create --peer laptop") {
		t.Fatalf("already: %q", got)
	}
}

func TestFormatAcceptCommand(t *testing.T) {
	tok := "abc123"
	if got := formatAcceptCommand(paths.DefaultPlatform(), tok); got != "tyd accept "+tok {
		t.Fatalf("default platform: %q", got)
	}
	if got := formatAcceptCommand("https://app.getfda.dev/", tok); got != "tyd accept "+tok {
		t.Fatalf("default with slash: %q", got)
	}
	custom := "http://127.0.0.1:8080"
	want := "tyd --platform " + custom + " accept " + tok
	if got := formatAcceptCommand(custom, tok); got != want {
		t.Fatalf("custom: %q want %q", got, want)
	}
}

func TestParseInviteToken(t *testing.T) {
	if got := parseInviteToken("deadbeef"); got != "deadbeef" {
		t.Fatalf("bare: %q", got)
	}
	if got := parseInviteToken("tyd accept deadbeef"); got != "deadbeef" {
		t.Fatalf("accept line: %q", got)
	}
	if got := parseInviteToken("tyd --platform http://127.0.0.1:1 accept deadbeef"); got != "deadbeef" {
		t.Fatalf("with platform: %q", got)
	}
	if got := parseInviteToken("tyd accept"); got != "" {
		t.Fatalf("missing token: %q", got)
	}
}

func TestInviteTTLCursorOffsets(t *testing.T) {
	up, down := inviteTTLCursorOffsets(false)
	if up != 4 || down != 3 {
		t.Fatalf("no relay: up=%d down=%d", up, down)
	}
	up, down = inviteTTLCursorOffsets(true)
	if up != 5 || down != 4 {
		t.Fatalf("with relay: up=%d down=%d", up, down)
	}
}

func TestPrintInviteResult(t *testing.T) {
	var errBuf, outBuf bytes.Buffer
	printInviteResult(&errBuf, &outBuf, inviteResult{
		Kind:     "registered",
		URL:      "https://app.getfda.dev/abc",
		Approval: "full",
		Platform: paths.DefaultPlatform(),
		Relay:    paths.DefaultRelay(),
		Token:    "tok1",
		TTL:      controlpanel.InviteTTL,
	})
	errOut := errBuf.String()
	for _, want := range []string{
		"Registered with Control Panel.",
		"url",
		"https://app.getfda.dev/abc",
		"approval",
		"full",
		"invite ttl",
		"relay",
		paths.DefaultRelay(),
		"Copy and run on the peer:",
		"tyd accept tok1",
	} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("missing %q in stderr:\n%s", want, errOut)
		}
	}
	if strings.Contains(errOut, "waiting for accept") {
		t.Fatalf("unexpected waiting line in:\n%s", errOut)
	}
	ttlIdx := strings.Index(errOut, "invite ttl")
	copyIdx := strings.Index(errOut, "Copy and run on the peer:")
	if ttlIdx < 0 || copyIdx < 0 || ttlIdx > copyIdx {
		t.Fatalf("invite ttl should sit with metadata above copy hint:\n%s", errOut)
	}

	if strings.Count(errOut, "tyd accept tok1") != 1 {
		t.Fatalf("accept command should appear once on stderr:\n%s", errOut)
	}
	if got := strings.TrimSpace(outBuf.String()); got != "tyd accept tok1" {
		t.Fatalf("stdout %q", got)
	}
}

func TestEnsureIdentityOnRegisterAccept(t *testing.T) {
	dir := t.TempDir()
	addr, srv, err := startTestCP(t)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	serverDir := filepath.Join(dir, "server")
	clientDir := filepath.Join(dir, "client")
	_ = os.MkdirAll(serverDir, 0o700)
	_ = os.MkdirAll(clientDir, 0o700)

	platform := "http://" + addr
	sOpts := options{
		identity: filepath.Join(serverDir, "id_ed25519"),
		trust:    filepath.Join(serverDir, "trusted.json"),
		peers:    filepath.Join(serverDir, "peers.json"),
		platform: platform,
		approval: "full",
		noWait:   true,
		cmd:      "register",
	}
	acceptLine := strings.TrimSpace(captureStdout(t, func() {
		if err := run(sOpts); err != nil {
			t.Fatal(err)
		}
	}))
	token := parseInviteToken(acceptLine)
	if token == "" {
		t.Fatalf("empty invite from %q", acceptLine)
	}
	wantCmd := formatAcceptCommand(platform, token)
	if acceptLine != wantCmd {
		t.Fatalf("stdout accept command %q want %q", acceptLine, wantCmd)
	}
	if _, err := os.Stat(sOpts.identity); err != nil {
		t.Fatalf("server identity not auto-created: %v", err)
	}

	cOpts := options{
		identity: filepath.Join(clientDir, "id_ed25519"),
		trust:    filepath.Join(clientDir, "trusted.json"),
		peers:    filepath.Join(clientDir, "peers.json"),
		platform: platform,
		as:       "box",
		cmd:      "accept",
		rest:     []string{acceptLine},
	}
	peerID := strings.TrimSpace(captureStdout(t, func() {
		if err := run(cOpts); err != nil {
			t.Fatal(err)
		}
	}))
	if peerID == "" {
		t.Fatal("empty peer id")
	}
	if _, err := os.Stat(cOpts.identity); err != nil {
		t.Fatalf("client identity not auto-created: %v", err)
	}

	sState, err := peerstate.Load(sOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncPeersFromCP(sOpts, sState); err != nil {
		t.Fatal(err)
	}
	sPeers, err := peers.Load(sOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if sPeers.Registration == nil || sPeers.Registration.ID == "" {
		t.Fatal("missing server registration")
	}
	if len(sPeers.Peers) != 1 {
		t.Fatalf("server peers %+v", sPeers.Peers)
	}
	cPeers, err := peers.Load(cOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(cPeers.Peers) != 1 || cPeers.Peers[0].Nickname != "box" {
		t.Fatalf("client peers %+v", cPeers.Peers)
	}
	if cPeers.Peers[0].PublicKey == "" || sPeers.Peers[0].PublicKey == "" {
		t.Fatal("missing exchanged public keys")
	}
	if cPeers.Peers[0].ID != sPeers.Registration.ID {
		t.Fatalf("client peer id %s want %s", cPeers.Peers[0].ID, sPeers.Registration.ID)
	}
}

func TestRegisterWaitsForAccept(t *testing.T) {
	dir := t.TempDir()
	addr, srv, err := startTestCP(t)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	serverDir := filepath.Join(dir, "server")
	clientDir := filepath.Join(dir, "client")
	_ = os.MkdirAll(serverDir, 0o700)
	_ = os.MkdirAll(clientDir, 0o700)

	platform := "http://" + addr
	sOpts := options{
		identity: filepath.Join(serverDir, "id_ed25519"),
		trust:    filepath.Join(serverDir, "trusted.json"),
		peers:    filepath.Join(serverDir, "peers.json"),
		platform: platform,
		approval: "full",
		cmd:      "register",
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut := os.Stdout
	os.Stdout = w
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(sOpts)
		_ = w.Close()
	}()

	var acceptLine string
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 64)
	for time.Now().Before(deadline) {
		_ = r.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, readErr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if i := strings.IndexByte(string(buf), '\n'); i >= 0 {
				acceptLine = strings.TrimSpace(string(buf[:i]))
				break
			}
		}
		if readErr != nil && !errors.Is(readErr, os.ErrDeadlineExceeded) {
			break
		}
	}
	os.Stdout = oldOut
	if acceptLine == "" {
		t.Fatal("timed out waiting for accept command on stdout")
	}
	token := parseInviteToken(acceptLine)
	if token == "" {
		t.Fatalf("bad accept line %q", acceptLine)
	}

	cOpts := options{
		identity: filepath.Join(clientDir, "id_ed25519"),
		trust:    filepath.Join(clientDir, "trusted.json"),
		peers:    filepath.Join(clientDir, "peers.json"),
		platform: platform,
		as:       "laptop",
		cmd:      "accept",
		rest:     []string{token},
	}
	if err := run(cOpts); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("register wait: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("register did not exit after accept")
	}

	sPeers, err := peers.Load(sOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(sPeers.Peers) != 1 {
		t.Fatalf("server peers %+v", sPeers.Peers)
	}
}

func TestWaitForInviteExpired(t *testing.T) {
	cli := cpclient.New("http://127.0.0.1:1")
	err := waitForInviteAccept(options{}, cli, "d", "pk", "tok", time.Now().Add(-time.Second), nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("want expired, got %v", err)
	}
}

func TestParseIdleTimeout(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want time.Duration
	}{
		{"off", 0},
		{"none", 0},
		{"0", 0},
		{"", 0},
		{"8h", 8 * time.Hour},
		{"30m", 30 * time.Minute},
	} {
		got, err := parseIdleTimeout(tt.in)
		if err != nil {
			t.Fatalf("%q: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("%q = %s want %s", tt.in, got, tt.want)
		}
	}
	for _, bad := range []string{"soon", "-1h", "8"} {
		if _, err := parseIdleTimeout(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

// Changing the approval mode must keep the daemon id and the peer list.
func TestRunApprovalUpdatesModeWithoutReregister(t *testing.T) {
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.json")
	doc := &peers.File{
		Platform: "http://127.0.0.1:1",
		Registration: &peers.Registration{
			ID:           "daemon1",
			PublicKey:    "pk",
			ApprovalMode: "full",
		},
		Peers: []peers.Peer{{ID: "peer1", PublicKey: "pk2", Nickname: "laptop"}},
	}
	if err := peers.Save(peersPath, doc); err != nil {
		t.Fatal(err)
	}
	opts := options{cmd: "approval", rest: []string{"pre"}, peers: peersPath, platform: "http://127.0.0.1:1"}
	out := captureStdout(t, func() {
		if err := runApproval(opts); err != nil {
			t.Fatalf("runApproval: %v", err)
		}
	})
	if strings.TrimSpace(out) != "pre" {
		t.Fatalf("stdout %q", out)
	}
	got, err := peers.Load(peersPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Registration.ApprovalMode != "pre" {
		t.Fatalf("mode=%s", got.Registration.ApprovalMode)
	}
	if got.Registration.ID != "daemon1" {
		t.Fatalf("id changed to %s", got.Registration.ID)
	}
	if len(got.Peers) != 1 || got.Peers[0].Nickname != "laptop" {
		t.Fatalf("peers lost: %+v", got.Peers)
	}

	show := captureStdout(t, func() {
		if err := runApproval(options{cmd: "approval", peers: peersPath}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.TrimSpace(show) != "pre" {
		t.Fatalf("show stdout %q", show)
	}
}

func TestRunApprovalRejectsBadMode(t *testing.T) {
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.json")
	if err := peers.Save(peersPath, &peers.File{
		Registration: &peers.Registration{ID: "d", PublicKey: "pk", ApprovalMode: "full"},
	}); err != nil {
		t.Fatal(err)
	}
	err := runApproval(options{cmd: "approval", rest: []string{"sometimes"}, peers: peersPath})
	if err == nil || !strings.Contains(err.Error(), "full, pre, or post") {
		t.Fatalf("got %v", err)
	}
	if err := runApproval(options{cmd: "approval", rest: []string{"pre"}, peers: filepath.Join(dir, "missing.json")}); err == nil ||
		!strings.Contains(err.Error(), "not registered") {
		t.Fatalf("unregistered: %v", err)
	}
}

func TestAcceptAlreadyPairedNamesPeerAndHintsWhenLive(t *testing.T) {
	dir := t.TempDir()
	addr, srv, err := startTestCP(t)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	serverDir := filepath.Join(dir, "server")
	clientDir := filepath.Join(dir, "client")
	_ = os.MkdirAll(serverDir, 0o700)
	_ = os.MkdirAll(clientDir, 0o700)
	platform := "http://" + addr
	sOpts := options{
		identity: filepath.Join(serverDir, "id_ed25519"),
		trust:    filepath.Join(serverDir, "trusted.json"),
		peers:    filepath.Join(serverDir, "peers.json"),
		platform: platform,
		approval: "full",
		noWait:   true,
		cmd:      "register",
	}
	acceptLine := strings.TrimSpace(captureStdout(t, func() {
		if err := run(sOpts); err != nil {
			t.Fatal(err)
		}
	}))
	cOpts := options{
		identity: filepath.Join(clientDir, "id_ed25519"),
		trust:    filepath.Join(clientDir, "trusted.json"),
		peers:    filepath.Join(clientDir, "peers.json"),
		platform: platform,
		as:       "laptop",
		cmd:      "accept",
		rest:     []string{acceptLine},
	}
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := run(cOpts); err != nil {
				t.Fatal(err)
			}
		})
	})
	if !strings.Contains(stderr, "paired with ") || strings.Contains(stderr, "already paired") {
		t.Fatalf("first accept stderr: %q", stderr)
	}
	if strings.Contains(stderr, "session create") {
		t.Fatalf("offline peer should not suggest connect: %q", stderr)
	}
	peerID := strings.TrimSpace(stdout)
	if peerID == "" {
		t.Fatal("empty peer id")
	}

	sDoc, err := peers.Load(sOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if err := cpclient.New(platform).PublishEndpointFull(sDoc.Registration.ID, controlpanel.PublishEndpointRequest{
		PublicKey: sDoc.Registration.PublicKey,
		Addr:      "127.0.0.1:1",
		CertFP:    "ab",
	}); err != nil {
		t.Fatal(err)
	}
	sOpts.cmd = "invite"
	secondLine := strings.TrimSpace(captureStdout(t, func() {
		if err := run(sOpts); err != nil {
			t.Fatal(err)
		}
	}))
	cOpts.rest = []string{secondLine}
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := run(cOpts); err != nil {
				t.Fatal(err)
			}
		})
	})
	if strings.TrimSpace(stdout) != peerID {
		t.Fatalf("stdout %q want %q", stdout, peerID)
	}
	if !strings.Contains(stderr, "already paired with "+peerID+" (laptop)") {
		t.Fatalf("stderr missing peer: %q", stderr)
	}
	if !strings.Contains(stderr, "tyd session create --peer laptop") {
		t.Fatalf("stderr missing connect hint: %q", stderr)
	}
	cDoc, err := peers.Load(cOpts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(cDoc.Peers) != 1 || cDoc.Peers[0].Nickname != "laptop" {
		t.Fatalf("client peers %+v", cDoc.Peers)
	}
}
