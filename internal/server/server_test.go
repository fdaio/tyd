package server

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/protocol"
	"tyd/internal/session"
)

func startTestServer(t *testing.T) (string, ed25519.PrivateKey, *auth.Store) {
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
	if err := client.WaitSocket(sock, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return sock, key, trust
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
	sock, key, _ := startTestServer(t)
	dir := t.TempDir()
	info, err := client.Create(sock, key, client.CreateOpts{
		Rows:  24,
		Cols:  80,
		Shell: "/bin/sh",
		Cwd:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" {
		t.Fatal("empty id")
	}

	c, err := client.Dial(sock, key)
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

	listed, err := client.List(sock, key)
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
			if s.PID == 0 {
				t.Fatal("missing pid")
			}
		}
	}
	if !found {
		t.Fatal("session disappeared after client drop")
	}

	c2, err := client.Dial(sock, key)
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

	if err := client.CloseSession(sock, key, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsUnknownSession(t *testing.T) {
	sock, key, _ := startTestServer(t)
	err := client.CloseSession(sock, key, "does-not-exist")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectsUntrustedKey(t *testing.T) {
	sock, _, _ := startTestServer(t)
	_, other, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Dial(sock, other)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsUnauthenticatedCommand(t *testing.T) {
	sock, _, _ := startTestServer(t)
	nc, err := net.Dial("unix", sock)
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
	sock, admin, trust := startTestServer(t)
	info, err := client.Create(sock, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
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

	c, err := client.Dial(sock, reader)
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
	if err := client.WaitSocket(sock, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	sessA, err := client.Create(sock, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := client.Create(sock, admin, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(pub, sessA.ID, auth.CapAttach, auth.CapClose); err != nil {
		t.Fatal(err)
	}

	if err := client.CloseSession(sock, other, sessB.ID); err == nil {
		t.Fatal("other must not close session B")
	}

	c, err := client.Dial(sock, other)
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
