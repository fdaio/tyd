package session

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testOpts(t *testing.T) CreateOpts {
	t.Helper()
	dir := t.TempDir()
	return CreateOpts{
		Rows:  24,
		Cols:  80,
		Shell: "/bin/sh",
		Cwd:   dir,
		Env: []string{
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
			"HOME=" + dir,
			"TERM=xterm",
			"PS1=$ ",
		},
	}
}

func waitContains(t *testing.T, att *Attachment, acc []byte, sub string, timeout time.Duration) []byte {
	t.Helper()
	if bytes.Contains(acc, []byte(sub)) {
		return acc
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, err := att.RecvTimeout(time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for %q, got %q: %v", sub, acc, err)
		}
		acc = append(acc, b...)
		if bytes.Contains(acc, []byte(sub)) {
			return acc
		}
	}
	t.Fatalf("timeout waiting for %q, got %q", sub, acc)
	return acc
}

func TestCreateWriteDetachReattachClose(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()

	s, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.ID == "" {
		t.Fatal("empty session id")
	}
	if !s.Alive() {
		t.Fatal("shell not running after create")
	}

	att, snap, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker := "tyd-step1-" + filepath.Base(t.TempDir())
	if _, err := att.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}
	waitContains(t, att, snap, marker, 5*time.Second)

	if err := att.Resize(30, 100); err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.Rows != 30 || info.Cols != 100 {
		t.Fatalf("resize not recorded: %dx%d", info.Cols, info.Rows)
	}

	att.Detach()
	if !s.Alive() {
		t.Fatal("shell exited after detach")
	}
	if got := s.Info().State; got != string(StateDetached) {
		t.Fatalf("state after detach: %s", got)
	}

	att2, snap2, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := att2.Write([]byte("echo reattached-ok\n")); err != nil {
		t.Fatal(err)
	}
	waitContains(t, att2, snap2, "reattached-ok", 5*time.Second)
	att2.Detach()

	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !s.Alive() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s.Alive() {
		t.Fatal("shell still alive after close")
	}
	if _, err := m.Get(s.ID); err == nil {
		t.Fatal("closed session still listed")
	}
}

func TestAttachRejectsSecondWriter(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()
	if _, _, err := s.Attach(); err == nil {
		t.Fatal("expected second attach to fail")
	}
}

func TestSignalINTStopsSleep(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	att, snap, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()

	if _, err := att.Write([]byte("sleep 30\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := att.Signal("INT"); err != nil {
		t.Fatal(err)
	}
	if _, err := att.Write([]byte("echo after-int\n")); err != nil {
		t.Fatal(err)
	}
	out := waitContains(t, att, snap, "after-int", 5*time.Second)
	if strings.Contains(string(out), "tyd-never") {
		t.Fatal("unexpected")
	}
}
