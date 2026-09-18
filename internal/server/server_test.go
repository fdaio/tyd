package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/protocol"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func startTestServer(t *testing.T) (client.Endpoint, ed25519.PrivateKey, *auth.Store) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	sock := fmt.Sprintf("/tmp/tyd-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := New(sock, session.NewManager(), trust)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := client.WaitReady(ep, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return ep, key, trust
}

func waitOutput(t *testing.T, c *client.Conn, acc []byte, sub string, timeout time.Duration) []byte {
	t.Helper()
	if bytes.Contains(acc, []byte(sub)) {
		return acc
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = c.SetDeadline(deadline)
		f, err := c.Recv()
		if err != nil {
			t.Fatalf("waiting for %q, got %q: %v", sub, acc, err)
		}
		if f.Type == protocol.TypeOutput {
			acc = append(acc, f.Data...)
			if bytes.Contains(acc, []byte(sub)) {
				_ = c.SetDeadline(time.Time{})
				return acc
			}
		}
		if f.Type == protocol.TypeError {
			t.Fatalf("waiting for %q: %s (got %q)", sub, f.Error, acc)
		}
	}
	t.Fatalf("timeout waiting for %q, got %q", sub, acc)
	return acc
}

func waitDetached(t *testing.T, c *client.Conn, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = c.SetDeadline(deadline)
		f, err := c.Recv()
		if err != nil {
			t.Fatalf("waiting for detached: %v", err)
		}
		switch f.Type {
		case protocol.TypeDetached:
			_ = c.SetDeadline(time.Time{})
			return
		case protocol.TypeOutput:
			continue // drain trailing PTY output
		case protocol.TypeError:
			t.Fatalf("waiting for detached: %s", f.Error)
		}
	}
	t.Fatal("timeout waiting for detached")
}

func TestServerCreateDetachDropReattach(t *testing.T) {
	ep, key, _ := startTestServer(t)
	dir := t.TempDir()
	info, err := client.Create(ep, key, client.CreateOpts{
		Rows: 24, Cols: 80, Shell: "/bin/sh", Cwd: dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	c, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("got %s %s", f.Type, f.Error)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo persist-ok\n")}); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, c, nil, "persist-ok", 5*time.Second)
	_ = c.Close()

	deadline := time.Now().Add(2 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		listed, err := client.List(ep, key)
		if err != nil {
			t.Fatal(err)
		}
		found = false
		ready := false
		for _, s := range listed {
			if s.ID != info.ID {
				continue
			}
			found = true
			if s.State == string(session.StateClosed) {
				t.Fatal("session closed after client drop")
			}
			if s.State != string(session.StateAttached) {
				ready = true
			}
		}
		if found && ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatal("session disappeared after client drop")
	}

	c2, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = c2.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("reattach got %s %s", f.Type, f.Error)
	}
	if err := c2.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo back-again\n")}); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, c2, nil, "back-again", 5*time.Second)
	if err := client.CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsUnknownSession(t *testing.T) {
	ep, key, _ := startTestServer(t)
	if err := client.CloseSession(ep, key, "does-not-exist"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectsUntrustedKey(t *testing.T) {
	ep, _, _ := startTestServer(t)
	_, other, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Dial(ep, other)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsUnauthenticatedCommand(t *testing.T) {
	ep, _, _ := startTestServer(t)
	nc, err := net.Dial("unix", ep.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	chal, err := protocol.ReadFrame(nc)
	if err != nil {
		t.Fatal(err)
	}
	if chal.Type != protocol.TypeChallenge {
		t.Fatalf("got %s", chal.Type)
	}
	if err := protocol.WriteFrame(nc, protocol.Frame{Type: protocol.TypeCreate}); err != nil {
		t.Fatal(err)
	}
	resp, err := protocol.ReadFrame(nc)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("got %+v", resp)
	}
}

func TestAttachMissingSessionReportsNotFound(t *testing.T) {
	ep, admin, _ := startTestServer(t)
	c, err := client.Dial(ep, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: "missing-session-id"}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeError {
		t.Fatalf("got %+v", f)
	}
	if !strings.Contains(f.Error, "not found") {
		t.Fatalf("want not found, got %q", f.Error)
	}
	if strings.Contains(f.Error, "permission denied") {
		t.Fatalf("stale/missing session must not look like permission denied: %q", f.Error)
	}
}

func TestAttachWithoutWriteCannotType(t *testing.T) {
	ep, admin, trust := startTestServer(t)
	info, err := client.Create(ep, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := reader.Public().(ed25519.PublicKey)
	trust.Add("reader", pub, []auth.Cap{auth.CapList})
	if err := trust.Grant(pub, info.ID, auth.CapAttach); err != nil {
		t.Fatal(err)
	}

	c, err := client.Dial(ep, reader)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("attach: %s %s", f.Type, f.Error)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo no\n")}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetDeadline(deadline)
		f, err = c.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if f.Type == protocol.TypeOutput {
			continue
		}
		if f.Type == protocol.TypeError && strings.Contains(f.Error, "write") {
			return
		}
		t.Fatalf("expected write denied, got %+v", f)
	}
	t.Fatal("timed out waiting for write denial")
}

func TestSessionGrantDoesNotCrossSessions(t *testing.T) {
	admin, store, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := other.Public().(ed25519.PublicKey)
	store.Add("other", pub, nil)

	sock := fmt.Sprintf("/tmp/tyd-cross-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := New(sock, session.NewManager(), store)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ep := client.Endpoint{Kind: transport.KindUnix, Address: sock}
	if err := client.WaitReady(ep, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	sessA, err := client.Create(ep, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := client.Create(ep, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(pub, sessA.ID, auth.CapAttach, auth.CapClose); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseSession(ep, other, sessB.ID); err == nil {
		t.Fatal("other must not close session B")
	}

	c, err := client.Dial(ep, other)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: sessB.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeError || !strings.Contains(f.Error, "attach") {
		t.Fatalf("expected attach denied on B, got %+v", f)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: sessA.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("expected attach A, got %+v", f)
	}
}

func TestServerRequiresTrustStore(t *testing.T) {
	srv := New("/tmp/tyd-no-trust.sock", session.NewManager(), nil)
	if err := srv.Start(); err == nil {
		t.Fatal("expected error")
	}
}

func TestTLSStatusShowsTopology(t *testing.T) {
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmp.Addr().String()
	_ = tmp.Close()
	sock := fmt.Sprintf("/tmp/tyd-top-%d.sock", time.Now().UnixNano()%1_000_000)
	srv := NewWithConfig(Config{
		Socket: sock, Listen: addr, CertPath: cert, KeyPath: keyPath,
		Mgr: session.NewManager(), Trust: trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ep := client.Endpoint{Kind: transport.KindTLS, Address: addr, CertPath: cert}
	if err := client.WaitReady(ep, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.Info().TLS {
		t.Fatal("client info missing tls")
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeStatus}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeConnections {
		t.Fatalf("got %+v", f)
	}
	ok := false
	for _, ci := range f.Connections {
		if ci.Transport == "tls" && ci.TLS && ci.Principal == "admin" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("topology %+v", f.Connections)
	}
}

func TestPlainTCPCannotSpeakProtocol(t *testing.T) {
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmp.Addr().String()
	_ = tmp.Close()
	srv := NewWithConfig(Config{
		Listen: addr, CertPath: filepath.Join(dir, "s.crt"), KeyPath: filepath.Join(dir, "s.key"),
		Mgr: session.NewManager(), Trust: trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = protocol.ReadFrame(nc)
	if err == nil {
		t.Fatal("plain TCP should not yield a tyd challenge frame")
	}
	_ = key
}

func TestWatchLiveAndClosed(t *testing.T) {
	ep, key, _ := startTestServer(t)
	dir := t.TempDir()
	info, err := client.Create(ep, key, client.CreateOpts{
		Rows: 24, Cols: 80, Shell: "/bin/sh", Cwd: dir,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Produce output via attach, then detach.
	c, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("got %s %s", f.Type, f.Error)
	}
	marker := "watch-server-live"
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo " + marker + "\n")}); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, c, nil, marker, 5*time.Second)
	if err := c.Send(protocol.Frame{Type: protocol.TypeDetach}); err != nil {
		t.Fatal(err)
	}
	waitDetached(t, c, 5*time.Second)
	_ = c.Close()

	// Live watch should see ring + new output.
	wc, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := wc.Send(protocol.Frame{Type: protocol.TypeWatch, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = wc.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeWatching {
		t.Fatalf("got %s %s", f.Type, f.Error)
	}
	acc := waitOutput(t, wc, nil, marker, 5*time.Second)

	ac, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := ac.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = ac.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("attach while watch: %s %s", f.Type, f.Error)
	}
	live2 := "watch-live-2"
	if err := ac.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo " + live2 + "\n")}); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, wc, acc, live2, 5*time.Second)
	_ = ac.Send(protocol.Frame{Type: protocol.TypeDetach})
	_ = ac.Close()
	_ = wc.Send(protocol.Frame{Type: protocol.TypeDetach})
	_ = wc.Close()

	if err := client.CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := client.List(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range listed {
		if s.ID == info.ID {
			found = true
			if s.State != string(session.StateClosed) {
				t.Fatalf("want CLOSED, got %s", s.State)
			}
		}
	}
	if !found {
		t.Fatal("closed session not in list")
	}

	// Historical watch: ring then exit.
	hc, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	if err := hc.Send(protocol.Frame{Type: protocol.TypeWatch, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = hc.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeWatching {
		t.Fatalf("got %s %s", f.Type, f.Error)
	}
	var hist []byte
	sawExit := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = hc.SetDeadline(deadline)
		f, err = hc.Recv()
		if err != nil {
			break
		}
		switch f.Type {
		case protocol.TypeOutput:
			hist = append(hist, f.Data...)
		case protocol.TypeExit:
			sawExit = true
			goto done
		case protocol.TypeDetached:
			sawExit = true
			goto done
		}
	}
done:
	if !bytes.Contains(hist, []byte(marker)) {
		t.Fatalf("history missing marker: %q", hist)
	}
	if !sawExit {
		t.Fatal("expected exit after closed watch history")
	}
}

func TestCloseAlreadyClosedErrors(t *testing.T) {
	ep, key, _ := startTestServer(t)
	info, err := client.Create(ep, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
	err = client.CloseSession(ep, key, info.ID)
	if err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("got %v", err)
	}
}

func startApprovalServer(t *testing.T, mode string) (unixEP, tlsEP client.Endpoint, admin ed25519.PrivateKey, getAudits func() []audit.Event) {
	t.Helper()
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmp.Addr().String()
	_ = tmp.Close()
	sock := fmt.Sprintf("/tmp/tyd-appr-%d.sock", time.Now().UnixNano()%1_000_000)
	var (
		mu     sync.Mutex
		events []audit.Event
	)
	srv := NewWithConfig(Config{
		Socket: sock, Listen: addr, CertPath: cert, KeyPath: keyPath,
		Mgr: session.NewManager(), Trust: trust, ApprovalMode: mode,
		Audit: audit.FuncSink(func(e audit.Event) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		}),
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	unixEP = client.Endpoint{Kind: transport.KindUnix, Address: sock}
	tlsEP = client.Endpoint{Kind: transport.KindTLS, Address: addr, CertPath: cert}
	if err := client.WaitReady(unixEP, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitReady(tlsEP, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return unixEP, tlsEP, key, func() []audit.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.Event(nil), events...)
	}
}

func hasAudit(events []audit.Event, kind audit.Kind, sessionID string) bool {
	for _, e := range events {
		if e.Kind == kind && e.SessionID == sessionID {
			return true
		}
	}
	return false
}

func TestPreTLSCreatePendingThenUnixApprove(t *testing.T) {
	unixEP, tlsEP, key, _ := startApprovalServer(t, "pre")
	dir := t.TempDir()
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: dir})
	if err != nil {
		t.Fatal(err)
	}
	if info.State != string(session.StatePending) {
		t.Fatalf("state=%s", info.State)
	}
	c, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeError || !strings.Contains(f.Error, "pending approval") {
		t.Fatalf("attach want pending error, got %+v", f)
	}

	approved, err := client.Approve(unixEP, key, info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if approved.State != string(session.StateDetached) {
		t.Fatalf("after approve %s", approved.State)
	}

	c2, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = c2.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("attach after approve: %+v", f)
	}
	_ = client.CloseSession(unixEP, key, info.ID)
}

func TestPreUnixCreateBypassesPending(t *testing.T) {
	unixEP, _, key, _ := startApprovalServer(t, "pre")
	info, err := client.Create(unixEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if info.State == string(session.StatePending) {
		t.Fatal("unix create under pre must not be pending")
	}
	if info.State != string(session.StateDetached) {
		t.Fatalf("state=%s", info.State)
	}
	_ = client.CloseSession(unixEP, key, info.ID)
}

func TestFullCreateNoPending(t *testing.T) {
	_, tlsEP, key, _ := startApprovalServer(t, "full")
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if info.State != string(session.StateDetached) {
		t.Fatalf("state=%s", info.State)
	}
	_ = client.CloseSession(tlsEP, key, info.ID)
}

func TestPostCreateCloseEmitsAudit(t *testing.T) {
	unixEP, tlsEP, key, getAudits := startApprovalServer(t, "post")
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if info.State == string(session.StatePending) {
		t.Fatal("post must auto-create")
	}
	if err := client.CloseSession(unixEP, key, info.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events := getAudits()
		if hasAudit(events, audit.KindCreate, info.ID) && hasAudit(events, audit.KindClose, info.ID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("audit missing for %s: %+v", info.ID, getAudits())
}

// full is the default mode and must still audit when a sink is configured.
func TestFullModeStillAudits(t *testing.T) {
	unixEP, tlsEP, key, getAudits := startApprovalServer(t, "full")
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAudit(getAudits(), audit.KindCreate, info.ID) {
		t.Fatalf("no create event: %+v", getAudits())
	}
	_ = client.CloseSession(unixEP, key, info.ID)
}

// Under pre, a second remote attach needs a fresh decision: the approval that
// came with the create is spent by the first attach.
func TestPreReattachNeedsNewApproval(t *testing.T) {
	unixEP, tlsEP, key, getAudits := startApprovalServer(t, "pre")
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Approve(unixEP, key, info.ID); err != nil {
		t.Fatal(err)
	}

	first, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := first.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("first attach: %+v", f)
	}
	if err := first.Send(protocol.Frame{Type: protocol.TypeDetach}); err != nil {
		t.Fatal(err)
	}
	for {
		f, err = first.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if f.Type == protocol.TypeDetached {
			break
		}
	}
	_ = first.Close()

	second, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = second.Recv()
	_ = second.Close()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeError || !strings.Contains(f.Error, "pending approval") {
		t.Fatalf("reattach want approval gate, got %+v", f)
	}
	if !hasAudit(getAudits(), audit.KindAttachPending, info.ID) {
		t.Fatalf("no attach_pending event: %+v", getAudits())
	}

	if _, err := client.Approve(unixEP, key, info.ID); err != nil {
		t.Fatalf("approve waiting attach: %v", err)
	}
	third, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if err := third.Send(protocol.Frame{Type: protocol.TypeAttach, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err = third.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeAttached {
		t.Fatalf("attach after second approval: %+v", f)
	}
	_ = client.CloseSession(unixEP, key, info.ID)
}

// Watch shows terminal output, so pre gates it like attach.
func TestPreGatesWatch(t *testing.T) {
	unixEP, tlsEP, key, _ := startApprovalServer(t, "pre")
	info, err := client.Create(unixEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(tlsEP, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeWatch, SessionID: info.ID}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeError || !strings.Contains(f.Error, "pending approval") {
		t.Fatalf("watch want approval gate, got %+v", f)
	}
	_ = client.CloseSession(unixEP, key, info.ID)
}

func TestApproveRejectedOverTLS(t *testing.T) {
	unixEP, tlsEP, key, _ := startApprovalServer(t, "pre")
	info, err := client.Create(tlsEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Approve(tlsEP, key, info.ID); err == nil || !strings.Contains(err.Error(), "unix") {
		t.Fatalf("approve over tls: %v", err)
	}
	if err := client.Reject(unixEP, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPendingApprovalsExpire(t *testing.T) {
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{
		Mgr: session.NewManager(), Trust: trust,
		ApprovalMode: "pre", ApprovalTTL: 20 * time.Millisecond,
	})
	st := &connState{
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "10.0.0.2:4242"},
		principal: trust.Add("laptop", key.Public().(ed25519.PublicKey), nil),
	}
	if err := srv.gateAttach(st, "sess1"); err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("first attach: %v", err)
	}
	waiting := srv.PendingApprovals()
	if len(waiting) != 1 || waiting[0].SessionID != "sess1" || waiting[0].Principal != "laptop" {
		t.Fatalf("pending=%+v", waiting)
	}
	if waiting[0].Transport != string(transport.KindTLS) || waiting[0].RemoteAddr != "10.0.0.2:4242" {
		t.Fatalf("pending lost connection detail: %+v", waiting[0])
	}

	time.Sleep(40 * time.Millisecond)
	if got := srv.PendingApprovals(); len(got) != 0 {
		t.Fatalf("stale request survived TTL: %+v", got)
	}
	if n := srv.decidePending("sess1", true); n != 0 {
		t.Fatalf("expired request approved: n=%d", n)
	}
	if err := srv.gateAttach(st, "sess1"); err == nil {
		t.Fatal("expired approval must not let an attach through")
	}
}

// A unix (local) connection is the operator and is never gated.
func TestGateSkipsUnix(t *testing.T) {
	_, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{Mgr: session.NewManager(), Trust: trust, ApprovalMode: "pre"})
	st := &connState{info: transport.Info{Transport: transport.KindUnix}}
	if err := srv.gateAttach(st, "sess1"); err != nil {
		t.Fatalf("unix attach gated: %v", err)
	}
	if got := srv.PendingApprovals(); len(got) != 0 {
		t.Fatalf("unix attach recorded: %+v", got)
	}
}

// QUIC is the preferred data-plane transport, so it must be gated like TLS.
func TestGateCoversQUIC(t *testing.T) {
	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewWithConfig(Config{Mgr: session.NewManager(), Trust: trust, ApprovalMode: "pre"})
	st := &connState{
		info:      transport.Info{Transport: transport.KindQUIC},
		principal: trust.Add("peer", key.Public().(ed25519.PublicKey), nil),
	}
	if err := srv.gateAttach(st, "sess1"); err == nil {
		t.Fatal("quic attach must be gated under pre")
	}
	if n := srv.decidePending("sess1", true); n != 1 {
		t.Fatalf("approved n=%d", n)
	}
	if err := srv.gateAttach(st, "sess1"); err != nil {
		t.Fatalf("approved quic attach: %v", err)
	}
	if err := srv.gateAttach(st, "sess1"); err == nil {
		t.Fatal("approval must be one-shot")
	}
}
