package server

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"tyd/internal/client"
	"tyd/internal/protocol"
	"tyd/internal/session"
)

func startTestServer(t *testing.T) string {
	t.Helper()
	sock := fmt.Sprintf("/tmp/tyd-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	srv := New(sock, session.NewManager())
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := client.WaitSocket(sock, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	return sock
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
	}
	t.Fatalf("timeout waiting for %q, got %q", sub, acc)
	return acc
}

func TestServerCreateDetachDropReattach(t *testing.T) {
	sock := startTestServer(t)
	dir := t.TempDir()
	info, err := client.Create(sock, client.CreateOpts{
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

	c, err := client.Dial(sock)
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
		t.Fatalf("got %s", f.Type)
	}
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo persist-ok\n")}); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, c, nil, "persist-ok", 5*time.Second)
	_ = c.Close()

	listed, err := client.List(sock)
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

	c2, err := client.Dial(sock)
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

	if err := client.CloseSession(sock, info.ID); err != nil {
		t.Fatal(err)
	}
}

func TestServerRejectsUnknownSession(t *testing.T) {
	sock := startTestServer(t)
	err := client.CloseSession(sock, "does-not-exist")
	if err == nil {
		t.Fatal("expected error")
	}
}
