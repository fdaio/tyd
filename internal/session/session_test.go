package session

import (
	"bytes"
	"io"
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
	got, err := m.Get(s.ID)
	if err != nil {
		t.Fatal("closed session should remain gettable:", err)
	}
	if got.Info().State != string(StateClosed) {
		t.Fatalf("state after close: %s", got.Info().State)
	}
	if err := m.Close(s.ID); err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("expected already closed, got %v", err)
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

func TestListSortAliveThenClosedByCreatedAt(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()

	s1, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	s3, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	s4, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	s1.CreatedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	s2.CreatedAt = time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	s3.CreatedAt = time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)
	s4.CreatedAt = time.Date(2024, 1, 4, 0, 0, 0, 0, time.UTC)

	if err := m.Close(s2.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(s4.ID); err != nil {
		t.Fatal(err)
	}

	list := m.List()
	if len(list) != 4 {
		t.Fatalf("len=%d", len(list))
	}
	// alive newest first: s3, s1; then closed newest first: s4, s2
	want := []string{s3.ID, s1.ID, s4.ID, s2.ID}
	for i, id := range want {
		if list[i].ID != id {
			t.Fatalf("pos %d: got %s want %s (states %v)", i, list[i].ID, id, []string{list[0].State, list[1].State, list[2].State, list[3].State})
		}
	}
	if list[2].State != string(StateClosed) || list[3].State != string(StateClosed) {
		t.Fatalf("closed should be last group: %+v", list)
	}
}

func TestCloseKeepsSessionInManager(t *testing.T) {
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
	marker := "keep-closed-" + filepath.Base(t.TempDir())
	if _, err := att.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}
	waitContains(t, att, snap, marker, 5*time.Second)
	att.Detach()

	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Info().State != string(StateClosed) {
		t.Fatalf("state %s", got.Info().State)
	}
	found := false
	for _, info := range m.List() {
		if info.ID == s.ID && info.State == string(StateClosed) {
			found = true
		}
	}
	if !found {
		t.Fatal("closed session missing from list")
	}
}

func waitWatcherContains(t *testing.T, w *Watcher, acc []byte, sub string, timeout time.Duration) []byte {
	t.Helper()
	if bytes.Contains(acc, []byte(sub)) {
		return acc
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, err := w.RecvTimeout(time.Until(deadline))
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

func TestWatchLiveReceivesOutput(t *testing.T) {
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

	w, snap, err := s.Watch()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	marker := "watch-live-" + filepath.Base(t.TempDir())
	if _, err := att.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}
	waitWatcherContains(t, w, snap, marker, 5*time.Second)
}

func TestWatchClosedDumpsRingThenEnds(t *testing.T) {
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
	marker := "watch-hist-" + filepath.Base(t.TempDir())
	if _, err := att.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}
	waitContains(t, att, snap, marker, 5*time.Second)
	att.Detach()

	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}

	w, hist, err := s.Watch()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !bytes.Contains(hist, []byte(marker)) {
		t.Fatalf("ring missing marker: %q", hist)
	}
	if !w.SessionClosed() {
		t.Fatal("watcher should see closed session")
	}
	_, err = w.Recv()
	if err != io.EOF {
		t.Fatalf("expected EOF from closed watch, got %v", err)
	}
}

func TestPendingApproveReject(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()

	s, err := m.CreatePending(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Info().State; got != string(StatePending) {
		t.Fatalf("state=%s", got)
	}
	if s.Alive() {
		t.Fatal("pending should not have a running shell")
	}
	if _, _, err := s.Attach(); err == nil || !strings.Contains(err.Error(), "pending approval") {
		t.Fatalf("attach: %v", err)
	}

	list := m.List()
	if len(list) != 1 || list[0].State != string(StatePending) {
		t.Fatalf("list=%+v", list)
	}

	approved, err := m.Approve(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := approved.Info().State; got != string(StateDetached) {
		t.Fatalf("after approve state=%s", got)
	}
	if !approved.Alive() {
		t.Fatal("shell should run after approve")
	}
	att, _, err := approved.Attach()
	if err != nil {
		t.Fatal(err)
	}
	att.Detach()
	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRejectRemovesPending(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.CreatePending(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reject(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(s.ID); err == nil {
		t.Fatal("expected not found after reject")
	}
}

func TestClosePendingRemoves(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.CreatePending(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(s.ID); err == nil {
		t.Fatal("expected not found after close pending")
	}
}

func TestPendingSortsAlive(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	closed, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(closed.ID); err != nil {
		t.Fatal(err)
	}
	pending, err := m.CreatePending(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	list := m.List()
	if len(list) < 2 {
		t.Fatalf("list=%+v", list)
	}
	if list[0].ID != pending.ID || list[0].State != string(StatePending) {
		t.Fatalf("pending should be first alive: %+v", list)
	}
	if list[len(list)-1].State != string(StateClosed) {
		t.Fatalf("closed last: %+v", list)
	}
}

func TestOnClosedCallback(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	ch := make(chan ClosedInfo, 1)
	m.SetOnClosed(func(info ClosedInfo) { ch <- info })
	s, err := m.Create(testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case info := <-ch:
		if info.SessionID != s.ID {
			t.Fatalf("id=%s", info.SessionID)
		}
		if info.CreatedAt.IsZero() || info.ClosedAt.IsZero() {
			t.Fatalf("timestamps %+v", info)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for onClosed")
	}
}

func TestReapIdleClosesUnattended(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.CloseAll)
	idle, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	busy, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := busy.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()

	if got := m.ReapIdle(0, time.Now()); got != nil {
		t.Fatalf("zero timeout must not reap: %v", got)
	}
	if got := m.ReapIdle(time.Hour, time.Now()); got != nil {
		t.Fatalf("fresh sessions must not reap: %v", got)
	}

	closed := m.ReapIdle(time.Nanosecond, time.Now().Add(time.Minute))
	if len(closed) != 1 || closed[0] != idle.ID {
		t.Fatalf("closed=%v want [%s]", closed, idle.ID)
	}
	if st := idle.State(); st != StateClosed {
		t.Fatalf("idle state=%s", st)
	}
	if st := busy.State(); st != StateAttached {
		t.Fatalf("attached session must survive, state=%s", st)
	}
}

func TestIdleSinceClearedWhileAttached(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.CloseAll)
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if s.IdleSince().IsZero() {
		t.Fatal("new detached session should be idle")
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if !s.IdleSince().IsZero() {
		t.Fatal("attached session must not be idle")
	}
	att.Detach()
	if s.IdleSince().IsZero() {
		t.Fatal("detached session should be idle again")
	}
}

func TestReapIdleLeavesPending(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.CloseAll)
	s, err := m.CreatePending(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.ReapIdle(time.Nanosecond, time.Now().Add(time.Hour)); got != nil {
		t.Fatalf("pending must not be reaped: %v", got)
	}
	if st := s.State(); st != StatePending {
		t.Fatalf("state=%s", st)
	}
}
