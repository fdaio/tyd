package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Dimension 1: state persistence.
//
// A human's shell is stateful: cd once, and every later command runs in
// that directory. An agent driving tyd must get the same guarantee —
// without re-stating the state in every command (the "cd a && ..." chain
// that forces guessing).

func TestDetCwdPersists(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	dir := t.TempDir()
	// cd once...
	d.RunOK("cd " + dir)
	// ...and a LATER command runs there. No chaining, no re-stating.
	out := d.Run("pwd")
	d.OutputContains(out, dir)
}

func TestDetCwdStacks(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	d.RunOK("cd " + base)
	d.RunOK("cd sub")
	out := d.Run("pwd")
	d.OutputContains(out, sub)
}

func TestDetEnvPersists(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	d.RunOK("export TYD_DET_PROBE=hello-determinism")
	out := d.Run("echo $TYD_DET_PROBE")
	d.OutputContains(out, "hello-determinism")
}

func TestDetSessionsAreIsolated(t *testing.T) {
	m, s1, _, cleanup := newLiveSession(t)
	defer cleanup()
	d1 := NewAgentDriver(t, s1)

	// A second, independent session.
	s2, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	d2 := NewAgentDriver(t, s2)

	dir := t.TempDir()
	d1.RunOK("cd " + dir)
	// Session 2 must not see session 1's cwd.
	out := d2.Run("pwd")
	if strings.Contains(out, dir) {
		t.Fatalf("session isolation broken: session 2 pwd shows session 1's dir %q", dir)
	}
}
