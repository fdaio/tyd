package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"tyd/internal/paths"
	"tyd/internal/server"
	"tyd/internal/session"
)

func TestParseArgs(t *testing.T) {
	def := paths.DefaultSocket()
	tests := []struct {
		name       string
		args       []string
		wantSocket string
		wantCmd    string
		wantRest   []string
		wantErr    bool
	}{
		{name: "empty", args: nil, wantSocket: def, wantCmd: ""},
		{name: "serve", args: []string{"serve"}, wantSocket: def, wantCmd: "serve"},
		{name: "socket before cmd", args: []string{"--socket", "/tmp/x.sock", "serve"}, wantSocket: "/tmp/x.sock", wantCmd: "serve"},
		{name: "socket after cmd", args: []string{"create", "--socket", "/tmp/y.sock"}, wantSocket: "/tmp/y.sock", wantCmd: "create"},
		{name: "socket equals", args: []string{"--socket=/tmp/z.sock", "list"}, wantSocket: "/tmp/z.sock", wantCmd: "list"},
		{name: "attach id", args: []string{"attach", "abc"}, wantSocket: def, wantCmd: "attach", wantRest: []string{"abc"}},
		{name: "help", args: []string{"--help"}, wantSocket: def, wantCmd: "help"},
		{name: "short help", args: []string{"-h"}, wantSocket: def, wantCmd: "help"},
		{name: "missing socket value", args: []string{"--socket"}, wantErr: true},
		{name: "unknown flag", args: []string{"--nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socket, cmd, rest, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if socket != tt.wantSocket || cmd != tt.wantCmd {
				t.Fatalf("socket=%q cmd=%q, want socket=%q cmd=%q", socket, cmd, tt.wantSocket, tt.wantCmd)
			}
			if strings.Join(rest, ",") != strings.Join(tt.wantRest, ",") {
				t.Fatalf("rest=%q want %q", rest, tt.wantRest)
			}
		})
	}
}

func TestRunRejectsBadUsage(t *testing.T) {
	if err := run("/tmp/x.sock", "attach", nil); err == nil {
		t.Fatal("attach without id")
	}
	if err := run("/tmp/x.sock", "close", nil); err == nil {
		t.Fatal("close without id")
	}
	if err := run("/tmp/x.sock", "wat", nil); err == nil {
		t.Fatal("unknown command")
	}
}

func TestRunCreateListClose(t *testing.T) {
	sock := fmt.Sprintf("/tmp/tyd-main-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := server.New(sock, session.NewManager())
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	id := strings.TrimSpace(captureStdout(t, func() {
		if err := run(sock, "create", nil); err != nil {
			t.Fatal(err)
		}
	}))
	if id == "" {
		t.Fatal("empty session id")
	}

	out := captureStdout(t, func() {
		if err := run(sock, "list", nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, id) {
		t.Fatalf("list missing %s: %q", id, out)
	}

	if err := run(sock, "close", []string{id}); err != nil {
		t.Fatal(err)
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
