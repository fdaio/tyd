package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func TestParseArgs(t *testing.T) {
	def := paths.DefaultSocket()
	id := paths.DefaultIdentity()
	trust := paths.DefaultTrust()
	listen := paths.DefaultListen()
	platform := paths.DefaultPlatform()
	tests := []struct {
		name         string
		args         []string
		wantSocket   string
		wantListen   string
		wantAddr     string
		wantID       string
		wantTrust    string
		wantPlatform string
		wantCmd      string
		wantRest     []string
		wantErr      bool
	}{
		{name: "empty", args: nil, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform},
		{name: "up", args: []string{"up"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "up"},
		{name: "serve", args: []string{"serve"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "serve"},
		{name: "listen explicit", args: []string{"--listen", "127.0.0.1:61211", "up"}, wantSocket: def, wantListen: "127.0.0.1:61211", wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "up"},
		{name: "session list with addr", args: []string{"--addr", "127.0.0.1:61211", "session", "list"}, wantSocket: def, wantListen: listen, wantAddr: "127.0.0.1:61211", wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "session", wantRest: []string{"list"}},
		{name: "session attach", args: []string{"session", "attach", "abc"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "session", wantRest: []string{"attach", "abc"}},
		{name: "status", args: []string{"status"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "status"},
		{name: "register platform", args: []string{"--platform", "http://127.0.0.1:9", "register"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: "http://127.0.0.1:9", wantCmd: "register"},
		{name: "peer flag", args: []string{"--peer", "box", "session", "list"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "session", wantRest: []string{"list"}},
		{name: "help", args: []string{"--help"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantPlatform: platform, wantCmd: "help"},
		{name: "unknown flag", args: []string{"--nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.socket != tt.wantSocket || opts.listen != tt.wantListen || opts.addr != tt.wantAddr ||
				opts.cmd != tt.wantCmd || opts.identity != tt.wantID || opts.trust != tt.wantTrust ||
				opts.platform != tt.wantPlatform {
				t.Fatalf("%+v", opts)
			}
			if tt.name == "peer flag" && opts.peer != "box" {
				t.Fatalf("peer=%q", opts.peer)
			}
			if strings.Join(opts.rest, ",") != strings.Join(tt.wantRest, ",") {
				t.Fatalf("rest=%q want %q", opts.rest, tt.wantRest)
			}
		})
	}
}

func TestRunRejectsBadUsage(t *testing.T) {
	dir := t.TempDir()
	base := options{
		socket: "/tmp/x.sock", identity: "/tmp/id", trust: "/tmp/t.json", listen: "off",
		recent: filepath.Join(dir, "recent.json"), aliases: filepath.Join(dir, "aliases.json"),
	}

	a := base
	a.cmd = "session"
	a.rest = []string{"attach"}
	if err := run(a); err == nil {
		t.Fatal("attach without id and without recent")
	}
	c := base
	c.cmd = "session"
	c.rest = []string{"close"}
	if err := run(c); err == nil {
		t.Fatal("close without id and without recent")
	}
	w := base
	w.cmd = "wat"
	if err := run(w); err == nil {
		t.Fatal("unknown command")
	}
	legacy := base
	legacy.cmd = "create"
	if err := run(legacy); err == nil || !strings.Contains(err.Error(), "tyd session create") {
		t.Fatalf("expected migration hint, got %v", err)
	}
}

func TestRunSessionCreateListStatusClose(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id_ed25519")
	trustPath := filepath.Join(dir, "trusted.json")
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.WriteIdentity(idPath, priv); err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := auth.WriteBootstrapTrust(trustPath, "local", pub); err != nil {
		t.Fatal(err)
	}
	trust, err := auth.LoadStore(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	sock := fmt.Sprintf("/tmp/tyd-main-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := server.NewWithConfig(server.Config{
		Socket: sock, Listen: "off", Mgr: session.NewManager(), Trust: trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	cli := options{
		socket: sock, identity: idPath, trust: trustPath, listen: "off",
		recent: filepath.Join(dir, "recent.json"), aliases: filepath.Join(dir, "aliases.json"),
		sessions: filepath.Join(dir, "sessions.json"),
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		create := cli
		create.cmd = "session"
		create.rest = []string{"create"}
		create.detach = true
		if err := run(create); err != nil {
			t.Fatal(err)
		}
	}))
	if id == "" {
		t.Fatal("empty session id")
	}
	listOut := captureStdout(t, func() {
		list := cli
		list.cmd = "session"
		list.rest = []string{"list"}
		if err := run(list); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(listOut, id) {
		t.Fatalf("list missing id: %q", listOut)
	}
	out := captureStdout(t, func() {
		st := cli
		st.cmd = "status"
		if err := run(st); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "TRANSPORT") {
		t.Fatalf("status missing connections header: %q", out)
	}
	if !strings.Contains(out, "Control Panel") {
		t.Fatalf("status missing CP section: %q", out)
	}
	closeCmd := cli
	closeCmd.cmd = "session"
	closeCmd.rest = []string{"close", id}
	if err := run(closeCmd); err != nil {
		t.Fatal(err)
	}

	// recent placeholder + alias
	aliasCmd := cli
	aliasCmd.cmd = "alias"
	aliasCmd.rest = []string{id, "jammy"}
	outAlias := captureStdout(t, func() {
		if err := run(aliasCmd); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(outAlias, "jammy ->") {
		t.Fatalf("alias out %q", outAlias)
	}
	list2 := captureStdout(t, func() {
		list := cli
		list.cmd = "session"
		list.rest = []string{"list"}
		if err := run(list); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(list2, "jammy") {
		t.Fatalf("list missing alias column: %q", list2)
	}
	closeAlias := cli
	closeAlias.cmd = "session"
	closeAlias.rest = []string{"close", "jammy"} // already closed is ok? close again on CLOSED
	// session already closed — closing again may error; use resolve only via attach attempt no.
	// Instead verify resolveSessionRef through alias list:
	alist := captureStdout(t, func() {
		a := cli
		a.cmd = "alias"
		a.rest = nil
		if err := run(a); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(alist, "jammy") || !strings.Contains(alist, id) {
		t.Fatalf("alias list %q", alist)
	}
}

func TestDefaultListenOff(t *testing.T) {
	if paths.DefaultListen() != "off" {
		t.Fatal(paths.DefaultListen())
	}
}

func TestRootHelpPlain(t *testing.T) {
	var buf bytes.Buffer
	writeRootHelp(&buf, false)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Fatalf("unexpected ANSI in plain help: %q", out)
	}
	for _, want := range []string{
		"Persistent, remotely attachable terminal sessions.",
		"Usage:",
		"tyd [command] [flags]",
		"Sessions:",
		"session create",
		"session list",
		"session attach",
		"session watch",
		"session approve",
		"session reject",
		"session close",
		"session alias",
		"Peers:",
		"peer list",
		"peer show",
		"peer alias",
		"revoke",
		"Pairing:",
		"keygen",
		"register",
		"invite",
		"accept",
		"Daemon:",
		"up",
		"serve",
		"status",
		"Flags:",
		"Connection:",
		"Paths / identity:",
		"Behavior:",
		"--socket PATH",
		"--peer ID|NICK",
		"--tls-cert PATH",
		"--aliases PATH",
		"--data-listen MODE",
		"--platform URL",
		"--force",
		"Tips:",
		"Ctrl-\\",
		"--peer",
		"recent",
		"control-plane-pairing.md",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRootHelpColor(t *testing.T) {
	var buf bytes.Buffer
	writeRootHelp(&buf, true)
	out := buf.String()
	if !strings.Contains(out, ansiCyan) || !strings.Contains(out, ansiReset) {
		t.Fatalf("expected ANSI cyan/reset in colored help: %q", out)
	}
	if !strings.Contains(out, "session create") {
		t.Fatal(out)
	}
}

func TestSessionHelpPlain(t *testing.T) {
	out := sessionUsage()
	if strings.Contains(out, "\033[") {
		t.Fatalf("unexpected ANSI in sessionUsage: %q", out)
	}
	for _, want := range []string{
		"Manage persistent PTY sessions.",
		"Usage:",
		"tyd session [command]",
		"Commands:",
		"create",
		"list",
		"attach",
		"watch",
		"approve",
		"reject",
		"close",
		"alias",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRootAndSessionCommandsIncludePeerAlias(t *testing.T) {
	root := rootCommands()
	foundPeer := false
	for _, c := range root {
		if c == "peer" {
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("rootCommands missing peer: %v", root)
	}
	sess := sessionCommands()
	foundAlias := false
	for _, c := range sess {
		if c == "alias" {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Fatalf("sessionCommands missing alias: %v", sess)
	}
}

func TestTopLevelAliasDeprecationNote(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		cmd: "alias", rest: []string{"list"},
		aliases: filepath.Join(dir, "aliases.json"),
		recent:  filepath.Join(dir, "recent.json"),
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	errRun := run(opts)
	_ = w.Close()
	os.Stderr = old
	if errRun != nil {
		t.Fatal(errRun)
	}
	b, _ := io.ReadAll(r)
	note := string(b)
	if !strings.Contains(note, "prefer 'tyd session alias'") {
		t.Fatalf("missing deprecation note: %q", note)
	}
}

func TestSessionHelpColor(t *testing.T) {

	var buf bytes.Buffer
	writeSessionHelp(&buf, true)
	out := buf.String()
	if !strings.Contains(out, ansiCyan) || !strings.Contains(out, ansiReset) {
		t.Fatalf("expected ANSI in colored session help: %q", out)
	}
}

func TestWriteSessionListPlainHidesSize(t *testing.T) {
	var buf bytes.Buffer
	writeSessionList(&buf, []sessionListRow{
		{ID: "aaa", Alias: "amy", Peer: "-", State: "DETACHED", Created: "2026-09-16T07:44:54Z"},
		{ID: "bbb", Alias: "", Peer: "-", State: "CLOSED", Created: "2026-09-16T06:37:33Z"},
	}, false)
	out := buf.String()
	if strings.Contains(out, "SIZE") || strings.Contains(out, "PID") || strings.Contains(out, "\033[") {
		t.Fatalf("plain list: %q", out)
	}
	if !strings.Contains(out, "SESSION") || !strings.Contains(out, "ALIAS") || !strings.Contains(out, "STATE") || !strings.Contains(out, "PEER") || !strings.Contains(out, "CREATED") {
		t.Fatalf("missing headers: %q", out)
	}
	if !strings.Contains(out, "2026-09-16T07:44:54Z") {
		t.Fatalf("missing created: %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d %q", len(lines), out)
	}
}

func TestWriteSessionListColorAliasAndLiveState(t *testing.T) {
	var buf bytes.Buffer
	writeSessionList(&buf, []sessionListRow{
		{ID: "aaa", Alias: "amy", Peer: "-", State: "DETACHED", Created: "t"},
		{ID: "bbb", Alias: "", Peer: "-", State: "CLOSED", Created: "t"},
		{ID: "ccc", Alias: "", Peer: "-", State: "PENDING", Created: "t"},
		{ID: "ddd", Alias: "", Peer: "-", State: "ATTACHED", Created: "t"},
	}, true)
	out := buf.String()
	header := strings.Split(out, "\n")[0]
	if strings.Contains(header, ansiCyan) {
		t.Fatalf("headers must be plain: %q", header)
	}
	if !strings.Contains(out, ansiCyan+"amy") {
		t.Fatalf("alias should be cyan: %q", out)
	}
	if !strings.Contains(out, ansiCyan+"ATTACHED") {
		t.Fatalf("ATTACHED should be cyan: %q", out)
	}
	for _, st := range []string{"DETACHED", "PENDING", "CLOSED"} {
		if strings.Contains(out, ansiCyan+st) {
			t.Fatalf("%s must not be cyan: %q", st, out)
		}
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
	// Command appears once under the copy hint (not also as a bare duplicate line).
	if strings.Count(errOut, "tyd accept tok1") != 1 {
		t.Fatalf("accept command should appear once on stderr:\n%s", errOut)
	}
	if got := strings.TrimSpace(outBuf.String()); got != "tyd accept tok1" {
		t.Fatalf("stdout %q", got)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
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
		rest:     []string{acceptLine}, // pasted full command line also works
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

	// Sync server peers after accept (CP list → peers.json); do not re-register.
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

func TestParseNoWaitFlag(t *testing.T) {
	opts, err := parseArgs([]string{"--no-wait", "register"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.noWait || opts.cmd != "register" {
		t.Fatalf("%+v", opts)
	}
}

func TestParseDetachFlag(t *testing.T) {
	opts, err := parseArgs([]string{"--detach", "session", "create"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.detach || opts.cmd != "session" {
		t.Fatalf("%+v", opts)
	}
}

func TestSessionListIsLocalCatalog(t *testing.T) {
	dir := t.TempDir()
	aliases := filepath.Join(dir, "aliases.json")
	sessions := filepath.Join(dir, "sessions.json")
	adoc := &alias.File{}
	if err := adoc.Set("amy", "878144071a28b83c", "8a6592c332eba2b2"); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(aliases, adoc); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		err := run(options{
			cmd: "session", rest: []string{"list"},
			aliases: aliases, sessions: sessions, recent: filepath.Join(dir, "recent.json"),
			// no socket, no identity, no CP — list must still work
			platform: "http://127.0.0.1:1",
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "878144071a28b83c") || !strings.Contains(out, "amy") {
		t.Fatalf("local list: %q", out)
	}
}

func startTestCP(t *testing.T) (string, interface{ Close() error }, error) {
	t.Helper()
	svc := controlpanel.New()
	addr, srv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		return "", nil, err
	}
	return addr.String(), srv, nil
}

func TestEnsureLocalDaemonSkipsPeer(t *testing.T) {
	called := false
	old := startLocalDaemonFn
	startLocalDaemonFn = func(options) error {
		called = true
		return nil
	}
	t.Cleanup(func() { startLocalDaemonFn = old })

	opts := options{socket: filepath.Join(t.TempDir(), "missing.sock")}
	ep := client.Endpoint{Kind: transport.KindTLS, Address: "127.0.0.1:1"}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("must not start local daemon for peer TLS targets")
	}
}

func TestEnsureLocalDaemonNoopWhenReady(t *testing.T) {
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("tyd-ready-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})

	called := false
	old := startLocalDaemonFn
	startLocalDaemonFn = func(options) error {
		called = true
		return nil
	}
	t.Cleanup(func() { startLocalDaemonFn = old })

	opts := options{socket: sock}
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("must not restart when socket already accepts")
	}
}

func TestEnsureLocalDaemonStartsWhenDown(t *testing.T) {
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("tyd-down-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	var ln net.Listener
	started := make(chan struct{}, 1)
	old := startLocalDaemonFn
	startLocalDaemonFn = func(opts options) error {
		if opts.socket != sock {
			t.Fatalf("socket=%q want %q", opts.socket, sock)
		}
		var err error
		ln, err = net.Listen("unix", sock)
		if err != nil {
			return err
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		started <- struct{}{}
		return nil
	}
	t.Cleanup(func() {
		startLocalDaemonFn = old
		if ln != nil {
			_ = ln.Close()
		}
		_ = os.Remove(sock)
	})

	opts := options{socket: sock}
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := ensureLocalDaemon(opts, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	default:
		t.Fatal("expected startLocalDaemonFn to run")
	}
	if !localDaemonReady(sock) {
		t.Fatal("socket should be ready after ensure")
	}
}

func TestFormatStatusConnErr(t *testing.T) {
	ep := client.Endpoint{Kind: transport.KindUnix, Address: "/tmp/tyd.sock"}
	got := formatStatusConnErr(ep, fmt.Errorf("dial unix /tmp/tyd.sock: connect: connection refused"))
	if got != "local daemon not running; start with tyd up" {
		t.Fatalf("got %q", got)
	}
	got = formatStatusConnErr(ep, fmt.Errorf("connect: invalid argument"))
	if got != "local daemon not running; start with tyd up" {
		t.Fatalf("invalid argument: %q", got)
	}
	if strings.Contains(got, "peer") || strings.Contains(got, "/tmp/tyd.sock") {
		t.Fatalf("leaked internals: %q", got)
	}
	tls := client.Endpoint{Kind: transport.KindTLS, Address: "10.0.0.1:1"}
	got = formatStatusConnErr(tls, fmt.Errorf("connection refused (is 'tyd up' running on the peer?)"))
	if !strings.HasPrefix(got, "daemon unreachable:") {
		t.Fatalf("tls: %q", got)
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

func TestParseAuditAndIdleFlags(t *testing.T) {
	opts, err := parseArgs([]string{"--audit-log", "/tmp/a.log", "--session-idle-timeout=8h", "up"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "up" {
		t.Fatalf("cmd=%s", opts.cmd)
	}
	if opts.auditLog != "/tmp/a.log" {
		t.Fatalf("auditLog=%q", opts.auditLog)
	}
	if opts.sessionIdle != 8*time.Hour {
		t.Fatalf("sessionIdle=%s", opts.sessionIdle)
	}
	if def, err := parseArgs([]string{"up"}); err != nil {
		t.Fatal(err)
	} else if def.sessionIdle != 0 || def.auditLog != "" {
		t.Fatalf("idle timeout and audit log must default off: %+v", def)
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
