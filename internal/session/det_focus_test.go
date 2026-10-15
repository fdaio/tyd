package session

import (
	"os"
	"testing"
	"time"

	"tyd/internal/live"
)

// Dimension 5: focus recovery ("不失焦").
//
// A session's state must survive everything short of an explicit close:
// detach/reattach, manager restart (live-agent re-adoption), and
// concurrent activity on sibling sessions.

func TestDetReattachKeepsState(t *testing.T) {
	m, s, root, cleanup := newLiveSession(t)
	defer cleanup()
	_ = root
	d := NewAgentDriver(t, s)

	dir := t.TempDir()
	d.RunOK("cd " + dir)
	d.RunOK("export FOCUS_PROBE=still-here")

	// Simulate detach: drop our handle, re-acquire the same session
	// from the manager by id, as attach would.
	s2, err := m.Get(s.ID)
	if err != nil {
		t.Fatalf("reattach failed: %v", err)
	}
	d2 := NewAgentDriver(t, s2)

	out := d2.Run("pwd")
	d2.OutputContains(out, dir)
	out = d2.Run("echo $FOCUS_PROBE")
	d2.OutputContains(out, "still-here")
}

func TestDetSurvivesManagerRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "detfocus")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	m1 := liveManager(t, root)
	s1, err := m1.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	d1 := NewAgentDriver(t, s1)
	dir := t.TempDir()
	d1.RunOK("cd " + dir)
	d1.RunOK("export RESTART_PROBE=survived")
	id := s1.ID
	// Graceful shutdown: live-agent survives, like `tyd up` stopping.
	m1.Shutdown()

	// A new manager over the same root re-adopts the live-agent,
	// like `tyd up` after a daemon restart.
	m2 := liveManager(t, root)
	defer m2.CloseAll()
	if _, err := m2.RestoreLive(); err != nil {
		t.Fatalf("RestoreLive failed: %v", err)
	}
	s2, err := m2.Get(id)
	if err != nil {
		t.Fatalf("attach after restart failed: %v", err)
	}
	// Wait until the re-adopted session is actually readable, with a
	// declared condition — no sleep-then-hope.
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := s2.Read(0, 0, time.Second, live.ReadConditions{})
		if err == nil && (len(res.Data) > 0 || res.AtEnd) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("re-adopted session never became readable: %v", err)
		}
	}
	d2 := NewAgentDriver(t, s2)
	out := d2.Run("pwd")
	d2.OutputContains(out, dir)
	out = d2.Run("echo $RESTART_PROBE")
	d2.OutputContains(out, "survived")
}
