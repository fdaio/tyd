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
	"tyd/internal/paths"
	"tyd/internal/server"
	"tyd/internal/session"
)

func TestParseArgs(t *testing.T) {
	def := paths.DefaultSocket()
	id := paths.DefaultIdentity()
	trust := paths.DefaultTrust()
	listen := paths.DefaultListen()
	tests := []struct {
		name       string
		args       []string
		wantSocket string
		wantListen string
		wantAddr   string
		wantID     string
		wantTrust  string
		wantCmd    string
		wantRest   []string
		wantErr    bool
	}{
		{name: "empty", args: nil, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust},
		{name: "serve", args: []string{"serve"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantCmd: "serve"},
		{name: "listen off", args: []string{"--listen", "off", "serve"}, wantSocket: def, wantListen: "off", wantID: id, wantTrust: trust, wantCmd: "serve"},
		{name: "session list with addr", args: []string{"--addr", "127.0.0.1:61211", "session", "list"}, wantSocket: def, wantListen: listen, wantAddr: "127.0.0.1:61211", wantID: id, wantTrust: trust, wantCmd: "session", wantRest: []string{"list"}},
		{name: "session attach", args: []string{"session", "attach", "abc"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantCmd: "session", wantRest: []string{"attach", "abc"}},
		{name: "status", args: []string{"status"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantCmd: "status"},
		{name: "help", args: []string{"--help"}, wantSocket: def, wantListen: listen, wantID: id, wantTrust: trust, wantCmd: "help"},
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
				opts.cmd != tt.wantCmd || opts.identity != tt.wantID || opts.trust != tt.wantTrust {
				t.Fatalf("%+v", opts)
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

func TestDefaultListenPort(t *testing.T) {
	if paths.DefaultListen() != "127.0.0.1:61211" {
		t.Fatal(paths.DefaultListen())
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
