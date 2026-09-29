package session

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/live"
)

func newLiveSession(t *testing.T) (*Manager, *Session, string, func()) {
	t.Helper()
	root, err := os.MkdirTemp("", "tsend")
	if err != nil {
		t.Fatal(err)
	}
	m := liveManager(t, root)
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return m, s, root, func() {
		m.CloseAll()
		_ = os.RemoveAll(root)
	}
}

// readUntil pulls pages until want appears or the deadline passes.
func readUntil(t *testing.T, s *Session, cursor, epoch uint64, want string, wait time.Duration) (uint64, uint64, string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var acc []byte
	for time.Now().Before(deadline) {
		res, err := s.Read(cursor, epoch, wait, live.ReadConditions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.CursorAhead || res.Dropped > 0 {
			cursor, epoch = res.CursorNext, res.Epoch
			continue
		}
		cursor, epoch = res.CursorNext, res.Epoch
		acc = append(acc, res.Data...)
		if want == "" || strings.Contains(string(acc), want) {
			return cursor, epoch, string(acc)
		}
		if res.AtEnd && !res.Exited {
			time.Sleep(20 * time.Millisecond)
		}
	}
	t.Fatalf("timeout waiting for %q, got %q", want, acc)
	return cursor, epoch, string(acc)
}

func TestSendInjectsKeystrokes(t *testing.T) {
	m, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	_ = m

	if _, err := s.Send([]byte("echo send-marker-1\n")); err != nil {
		t.Fatal(err)
	}
	_, _, out := readUntil(t, s, 0, 0, "send-marker-1", 2*time.Second)
	if !strings.Contains(out, "send-marker-1") {
		t.Fatalf("send output missing: %q", out)
	}
}

// A send must not start a shell that is gone.
func TestSendAfterExitRefuses(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	if _, err := s.Send([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if s.State() == StateExited {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.State() != StateExited {
		t.Skipf("shell did not report EXITED, state=%s", s.State())
	}
	if _, err := s.Send([]byte("echo should-not-run\n")); err == nil {
		t.Fatal("send on an exited session must fail")
	} else if !strings.Contains(err.Error(), "exited") {
		t.Fatalf("want an explicit exited error, got %v", err)
	}
}

// While someone holds the attach slot a send is refused, and the error must
// not name the holder.
// The live-agent has its own occupancy check, so a send that reaches it
// directly is refused too. The session-level check is not the only guard.
func TestSendAgentRefusesWhileAttached(t *testing.T) {
	_, s, root, cleanup := newLiveSession(t)
	defer cleanup()

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()

	dir := live.Dir(root, s.ID)
	_, err = live.DialSend(dir, []byte("echo direct\n"))
	if err == nil {
		t.Fatal("agent must refuse a send while attached")
	}
	if !strings.Contains(err.Error(), "session in use") {
		t.Fatalf("want a session-in-use error, got %v", err)
	}
}

func TestSendRefusedWhileAttached(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()

	_, err = s.Send([]byte("echo nope\n"))
	if err == nil {
		t.Fatal("send while attached must fail")
	}
	if !errors.Is(err, ErrSessionInUse) {
		t.Fatalf("want ErrSessionInUse, got %v", err)
	}
	if strings.Contains(err.Error(), attRemoteHint) {
		t.Fatalf("error leaks the holder: %v", err)
	}
}

const attRemoteHint = "admin"

// The slot frees up again once the attachment ends.
func TestSendAfterDetach(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send([]byte("echo x\n")); err == nil {
		t.Fatal("send while attached must fail")
	}
	att.Detach()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.Send([]byte("echo send-after-detach\n")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := s.Send([]byte("echo send-after-detach\n")); err != nil {
		t.Fatalf("send after detach: %v", err)
	}
	readUntil(t, s, 0, 0, "send-after-detach", 2*time.Second)
}

// Concurrent sends must all land and must not corrupt each other.
func TestSendConcurrent(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.Send([]byte("true\n"))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if s.State() == StateExited {
		t.Fatal("concurrent sends killed the shell")
	}
	readUntil(t, s, 0, 0, "", 500*time.Millisecond)
}

// A wait returns as soon as bytes arrive rather than sleeping it out.
func TestReadWaitReturnsOnData(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	go func() {
		time.Sleep(150 * time.Millisecond)
		_, _ = s.Send([]byte("echo wait-early\n"))
	}()

	start := time.Now()
	cursor, _, out := readUntil(t, s, 0, 0, "wait-early", 5*time.Second)
	elapsed := time.Since(start)
	if !strings.Contains(out, "wait-early") {
		t.Fatalf("missing marker: %q", out)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("wait did not return early, took %s", elapsed)
	}
	_ = cursor
}

// A wait with nothing to return gives up with empty data and at_end.
func TestReadWaitTimesOut(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	// Drain first so the log is settled.
	cursor, epoch, _ := readUntil(t, s, 0, 0, "", 200*time.Millisecond)

	start := time.Now()
	res, err := s.Read(cursor, epoch, 300*time.Millisecond, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if len(res.Data) != 0 {
		t.Fatalf("idle wait returned data: %q", res.Data)
	}
	if !res.AtEnd {
		t.Fatalf("idle wait must report at_end: %+v", res)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("returned too early: %s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("wait overshot: %s", elapsed)
	}
}

// A reset cursor comes back at once even when a wait was asked for.
func TestReadWaitSkipsOnCursorAhead(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	start := time.Now()
	res, err := s.Read(1<<40, 0, 5*time.Second, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CursorAhead {
		t.Fatalf("want cursor_ahead, got %+v", res)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cursor_ahead waited %s", elapsed)
	}
}

// Once the shell is gone, a read says so instead of parking. The flag alone
// is not enough: a read that waits out its full timeout before reporting
// exited would still be correct, and still make --follow crawl.
func TestReadExitedFlag(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	if _, err := s.Send([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if s.State() == StateExited {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Drain whatever the shell printed on its way out.
	cursor, epoch, _ := readUntil(t, s, 0, 0, "", 300*time.Millisecond)

	// Ask for a long wait. A dead shell must not make the caller sit it out.
	start := time.Now()
	res, err := s.Read(cursor, epoch, 5*time.Second, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if !res.Exited {
		t.Fatalf("want exited, got %+v", res)
	}
	if !res.AtEnd {
		t.Fatalf("want at_end, got %+v", res)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("read waited out its timeout on a dead shell: %s", elapsed)
	}
}

// A pending session refuses a send instead of starting a shell.
func TestSendPendingRefused(t *testing.T) {
	root, err := os.MkdirTemp("", "tsendp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	m := liveManager(t, root)
	defer m.CloseAll()

	s, err := m.CreatePending(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send([]byte("echo no\n")); err == nil {
		t.Fatal("send on a pending session must fail")
	} else if !strings.Contains(err.Error(), "pending") {
		t.Fatalf("want a pending error, got %v", err)
	}
}

// In-process sessions have no sequenced log and must say so.
func TestSendReadUnsupportedInProcess(t *testing.T) {
	m := NewManager()
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Send([]byte("echo x\n")); !errors.Is(err, ErrSendUnsupported) {
		t.Fatalf("want ErrSendUnsupported, got %v", err)
	}
	if _, err := s.Read(0, 0, 0, live.ReadConditions{}); !errors.Is(err, ErrReadUnsupported) {
		t.Fatalf("want ErrReadUnsupported, got %v", err)
	}
}

// A send large enough to fill the PTY buffer must not wedge the agent. The
// write blocks until the shell drains it, and the echo that drains it is
// recorded under the agent's state lock, so a send that holds that lock
// across the write deadlocks the whole session.
//
// The assertions are about send and read returning, not about what the
// shell prints. A kilobyte-long command line makes the shell redraw and
// mangle whatever comes next, so asserting on output here tests the shell.
func TestSendLargeDoesNotWedge(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	// Well past a PTY input buffer, so the write cannot complete at once.
	big := bytes.Repeat([]byte("x"), 8<<10)
	await := func(what string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			// A timeout here is acceptable backpressure; a hang is not.
			if err != nil {
				t.Logf("%s reported %v (backpressure, not a wedge)", what, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s hung instead of returning", what)
		}
	}
	await("large send", func() error { _, err := s.Send(big); return err })
	await("send after a large one", func() error { _, err := s.Send([]byte("true\n")); return err })
	await("read after a large send", func() error { _, err := s.Read(0, 0, 0, live.ReadConditions{}); return err })
}
