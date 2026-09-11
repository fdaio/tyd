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
	tests := []struct {
		name       string
		args       []string
		wantSocket string
		wantID     string
		wantTrust  string
		wantCmd    string
		wantRest   []string
		wantErr    bool
	}{
		{name: "empty", args: nil, wantSocket: def, wantID: id, wantTrust: trust, wantCmd: ""},
		{name: "serve", args: []string{"serve"}, wantSocket: def, wantID: id, wantTrust: trust, wantCmd: "serve"},
		{name: "socket before cmd", args: []string{"--socket", "/tmp/x.sock", "serve"}, wantSocket: "/tmp/x.sock", wantID: id, wantTrust: trust, wantCmd: "serve"},
		{name: "socket after cmd", args: []string{"create", "--socket", "/tmp/y.sock"}, wantSocket: "/tmp/y.sock", wantID: id, wantTrust: trust, wantCmd: "create"},
		{name: "identity", args: []string{"--identity", "/tmp/id", "list"}, wantSocket: def, wantID: "/tmp/id", wantTrust: trust, wantCmd: "list"},
		{name: "trust", args: []string{"--trust=/tmp/t.json", "serve"}, wantSocket: def, wantID: id, wantTrust: "/tmp/t.json", wantCmd: "serve"},
		{name: "attach id", args: []string{"attach", "abc"}, wantSocket: def, wantID: id, wantTrust: trust, wantCmd: "attach", wantRest: []string{"abc"}},
		{name: "help", args: []string{"--help"}, wantSocket: def, wantID: id, wantTrust: trust, wantCmd: "help"},
		{name: "short help", args: []string{"-h"}, wantSocket: def, wantID: id, wantTrust: trust, wantCmd: "help"},
		{name: "missing socket value", args: []string{"--socket"}, wantErr: true},
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
			if opts.socket != tt.wantSocket || opts.cmd != tt.wantCmd || opts.identity != tt.wantID || opts.trust != tt.wantTrust {
				t.Fatalf("%+v", opts)
			}
			if strings.Join(opts.rest, ",") != strings.Join(tt.wantRest, ",") {
				t.Fatalf("rest=%q want %q", opts.rest, tt.wantRest)
			}
		})
	}
}

func TestRunRejectsBadUsage(t *testing.T) {
	base := options{socket: "/tmp/x.sock", identity: "/tmp/id", trust: "/tmp/t.json"}
	a := base
	a.cmd = "attach"
	if err := run(a); err == nil {
		t.Fatal("attach without id")
	}
	c := base
	c.cmd = "close"
	if err := run(c); err == nil {
		t.Fatal("close without id")
	}
	w := base
	w.cmd = "wat"
	if err := run(w); err == nil {
		t.Fatal("unknown command")
	}
}

func TestRunCreateListClose(t *testing.T) {
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
	srv := server.New(sock, session.NewManager(), trust)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	cli := options{socket: sock, identity: idPath, trust: trustPath}
	id := strings.TrimSpace(captureStdout(t, func() {
		create := cli
		create.cmd = "create"
		if err := run(create); err != nil {
			t.Fatal(err)
		}
	}))
	if id == "" {
		t.Fatal("empty session id")
	}

	out := captureStdout(t, func() {
		list := cli
		list.cmd = "list"
		if err := run(list); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, id) {
		t.Fatalf("list missing %s: %q", id, out)
	}

	closeCmd := cli
	closeCmd.cmd = "close"
	closeCmd.rest = []string{id}
	if err := run(closeCmd); err != nil {
		t.Fatal(err)
	}
}

func TestKeygenWritesIdentityAndTrust(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		trust:    filepath.Join(dir, "trusted.json"),
		cmd:      "keygen",
	}
	if err := runKeygen(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadIdentity(opts.identity); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadStore(opts.trust); err != nil {
		t.Fatal(err)
	}
	if err := runKeygen(opts); err == nil {
		t.Fatal("expected refuse overwrite")
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
