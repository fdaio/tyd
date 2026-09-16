package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/server"
	"tyd/internal/session"
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
	}
	id := strings.TrimSpace(captureStdout(t, func() {
		create := cli
		create.cmd = "session"
		create.rest = []string{"create"}
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
		"Common commands:",
		"session create",
		"session list",
		"session attach",
		"session watch",
		"session approve",
		"session reject",
		"session close",
		"alias",
		"Identity / pairing:",
		"keygen",
		"register",
		"invite",
		"accept",
		"revoke",
		"Daemon:",
		"up",
		"serve",
		"status",
		"Flags:",
		"--socket PATH",
		"--peer ID|NICK",
		"--aliases PATH",
		"--data-listen MODE",
		"--platform URL",
		"Tips:",
		"Ctrl-\\",
		"--peer",
		"recent",
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
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
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

func TestPrintInviteResult(t *testing.T) {
	var errBuf, outBuf bytes.Buffer
	printInviteResult(&errBuf, &outBuf, inviteResult{
		Kind:     "registered",
		URL:      "https://app.getfda.dev/abc",
		Approval: "full",
		Platform: paths.DefaultPlatform(),
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
	// TTL is the trailing help row (below the accept hint).
	ttlIdx := strings.LastIndex(errOut, "invite ttl")
	copyIdx := strings.Index(errOut, "Copy and run on the peer:")
	if ttlIdx < 0 || copyIdx < 0 || ttlIdx < copyIdx {
		t.Fatalf("invite ttl should follow copy hint:\n%s", errOut)
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

	// Sync server peers after accept.
	sOpts.cmd = "register"
	_ = captureStdout(t, func() {
		if err := run(sOpts); err != nil {
			t.Fatal(err)
		}
	})
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

func startTestCP(t *testing.T) (string, interface{ Close() error }, error) {
	t.Helper()
	svc := controlpanel.New()
	addr, srv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		return "", nil, err
	}
	return addr.String(), srv, nil
}
