package server

import (
	"crypto/ed25519"
	"sync"
	"testing"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/transport"
)

// captureSink collects audit events for assertions.
type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureSink) Log(e audit.Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *captureSink) reads() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []audit.Event
	for _, e := range c.events {
		if e.Kind == audit.KindRead {
			out = append(out, e)
		}
	}
	return out
}

func (c *captureSink) byKind(k audit.Kind) []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []audit.Event
	for _, e := range c.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func (c *captureSink) reset() {
	c.mu.Lock()
	c.events = nil
	c.mu.Unlock()
}

func TestAuditReadRecordsOnlyBrokenPages(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st := &connState{
		principal: &auth.Principal{Name: "laptop", Pub: priv.Public().(ed25519.PublicKey)},
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "10.0.0.9:5555"},
	}
	sink := &captureSink{}
	srv := &Server{cfg: Config{Audit: sink, ApprovalMode: "pre"}}

	cases := []struct {
		name        string
		cursorAhead bool
		dropped     uint64
		want        int
		reason      string
	}{
		{"plain page", false, 0, 0, ""},
		{"plain page at end", false, 0, 0, ""},
		{"cursor reset", true, 0, 1, "cursor_reset"},
		{"prefix already gone", false, 4096, 1, "dropped_prefix"},
		// A reset is the stronger signal: the reader lost its place entirely.
		{"reset wins over dropped", true, 4096, 1, "cursor_reset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink.reset()
			srv.auditRead(st, "sess1", tc.cursorAhead, tc.dropped)
			got := sink.reads()
			if len(got) != tc.want {
				t.Fatalf("got %d events, want %d", len(got), tc.want)
			}
			if tc.want == 0 {
				return
			}
			if got[0].Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", got[0].Reason, tc.reason)
			}
			if got[0].SessionID != "sess1" {
				t.Fatalf("session = %q", got[0].SessionID)
			}
			// The event must say who read and from where, without saying what.
			if got[0].Principal != "laptop" {
				t.Fatalf("principal = %q", got[0].Principal)
			}
			if got[0].RemoteAddr != "10.0.0.9:5555" {
				t.Fatalf("remote = %q", got[0].RemoteAddr)
			}
			if got[0].Transport != string(transport.KindTLS) {
				t.Fatalf("transport = %q", got[0].Transport)
			}
		})
	}
}

// A unix connection is the local operator, but a reset cursor is still a reset
// cursor: the rule keys on the reply, not on who asked.
func TestAuditReadIgnoresTransport(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	srv := &Server{cfg: Config{Audit: sink, ApprovalMode: "pre"}}
	st := &connState{
		principal: &auth.Principal{Name: "local", Pub: priv.Public().(ed25519.PublicKey)},
		info:      transport.Info{Transport: transport.KindUnix},
	}
	srv.auditRead(st, "sess1", true, 0)
	got := sink.reads()
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Transport != string(transport.KindUnix) {
		t.Fatalf("transport = %q", got[0].Transport)
	}
}
