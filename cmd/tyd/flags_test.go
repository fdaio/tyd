package main

import (
	"strings"
	"testing"
	"time"

	"tyd/internal/paths"
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

func TestDefaultListenOff(t *testing.T) {
	if paths.DefaultListen() != "off" {
		t.Fatal(paths.DefaultListen())
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
