package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
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
	base := options{socket: "/tmp/x.sock", identity: "/tmp/id", trust: "/tmp/t.json", listen: "off"}

	a := base
	a.cmd = "session"
	a.rest = []string{"attach"}
	if err := run(a); err == nil {
		t.Fatal("attach without id")
	}
	c := base
	c.cmd = "session"
	c.rest = []string{"close"}
	if err := run(c); err == nil {
		t.Fatal("close without id")
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

	cli := options{socket: sock, identity: idPath, trust: trustPath, listen: "off"}
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
		t.Fatalf("status missing header: %q", out)
	}
	closeCmd := cli
	closeCmd.cmd = "session"
	closeCmd.rest = []string{"close", id}
	if err := run(closeCmd); err != nil {
		t.Fatal(err)
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
		"session close",
		"Identity / pairing:",
		"keygen",
		"register",
		"accept",
		"Daemon:",
		"up",
		"serve",
		"status",
		"Flags:",
		"--socket PATH",
		"--peer ID|NICK",
		"--data-listen MODE",
		"--platform URL",
		"Tips:",
		"Ctrl-\\",
		"--peer",
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
		cmd:      "register",
	}
	token := strings.TrimSpace(captureStdout(t, func() {
		if err := run(sOpts); err != nil {
			t.Fatal(err)
		}
	}))
	if token == "" {
		t.Fatal("empty invite")
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
		rest:     []string{token},
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

func startTestCP(t *testing.T) (string, interface{ Close() error }, error) {
	t.Helper()
	svc := controlpanel.New()
	addr, srv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		return "", nil, err
	}
	return addr.String(), srv, nil
}
