package server

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/session"
	"tyd/internal/transport"
)

type auditCollector struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *auditCollector) Log(e audit.Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *auditCollector) denied() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Kind == audit.KindDenied {
			return true
		}
	}
	return false
}

func startQuotaServer(t *testing.T, cfg Config) (client.Endpoint, ed25519.PrivateKey, *auditCollector) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	sock := fmt.Sprintf("/tmp/tyd-quota-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	collector := &auditCollector{}
	cfg.Socket = sock
	cfg.Mgr = session.NewManager()
	cfg.Trust = trust
	cfg.Audit = collector
	srv := NewWithConfig(cfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := client.WaitReady(ep, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return ep, key, collector
}

func TestPerPeerSessionLimit(t *testing.T) {
	ep, key, auditSink := startQuotaServer(t, Config{MaxSessionsPerPeer: 1})
	if _, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	_, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "session limit") {
		t.Fatalf("second create error = %v, want a session limit", err)
	}
	if !auditSink.denied() {
		t.Error("the refusal was not audited as denied")
	}
}

func TestTotalSessionLimit(t *testing.T) {
	ep, key, _ := startQuotaServer(t, Config{MaxSessionsTotal: 1})
	if _, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	_, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "session limit") {
		t.Fatalf("second create error = %v, want a session limit", err)
	}
}

func TestZeroLimitsAreUnlimited(t *testing.T) {
	ep, key, _ := startQuotaServer(t, Config{})
	for i := 0; i < 2; i++ {
		if _, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
}
