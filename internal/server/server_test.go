package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	listed, err := client.List(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range listed {
		if s.ID == info.ID {
			found = true
			if s.State == string(session.StateClosed) {
				t.Fatal("session closed after client drop")
			}
		}
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
