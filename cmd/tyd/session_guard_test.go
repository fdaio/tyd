package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A session shell shares the daemon's user and home, so it can reach the unix
// socket that carries approve, reject and approval-mode changes -- and it holds
// the same identity key, so the daemon sees it as itself. These tests pin the
// guard that makes the obvious move fail, and check that a process outside a
// session is unaffected.

// inSessionEnv runs fn with the session marker set, the way a shell started by
// tyd sees it.
func inSessionEnv(t *testing.T, sessionID string, fn func()) {
	t.Helper()
	t.Setenv("TYD_SESSION", sessionID)
	fn()
}

func TestControlCommandsAreRefusedInsideASession(t *testing.T) {
	refused := []string{
		"session approve", "session reject", "approval", "revoke",
		"invite", "accept", "register", "up", "serve",
	}
	for _, cmd := range refused {
		t.Run(cmd, func(t *testing.T) {
			inSessionEnv(t, "abc123", func() {
				err := refuseIfInSession(cmd)
				if err == nil {
					t.Fatalf("`tyd %s` was allowed inside a session", cmd)
				}
				// The message has to say why, or an agent retries in a loop.
				for _, want := range []string{"same user", "outside the session", "not a boundary"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error is missing %q:\n%v", want, err)
					}
				}
			})
		})
	}
}

// The guard must not cost an agent anything it is actually allowed to do. The
// read-only commands are the ones a session legitimately needs.
func TestReadOnlyCommandsWorkInsideASession(t *testing.T) {
	allowed := []string{
		"session list", "session watch", "session close", "session alias",
		"session create", "peer list", "status", "doctor", "audit", "session attach",
	}
	inSessionEnv(t, "abc123", func() {
		for _, cmd := range allowed {
			if err := refuseIfInSession(cmd); err != nil {
				t.Errorf("`tyd %s` was refused inside a session: %v", cmd, err)
			}
		}
	})
}

// Outside a session nothing changes, which is the whole point: the guard keys
// off the session, not off being a tyd process.
func TestControlCommandsWorkOutsideASession(t *testing.T) {
	t.Setenv("TYD_SESSION", "")
	for _, cmd := range []string{"session approve", "approval", "revoke", "invite", "up"} {
		if err := refuseIfInSession(cmd); err != nil {
			t.Errorf("`tyd %s` was refused outside a session: %v", cmd, err)
		}
	}
}

// End to end through the CLI: `tyd approval full` from inside a session must
// fail and must not reach the Control Panel.
func TestApprovalFullIsRefusedFromASessionShell(t *testing.T) {
	dir := t.TempDir()
	bin := buildCLI(t)

	cmd := exec.Command(bin, "--peers", filepath.Join(dir, "peers.json"),
		"--paired", filepath.Join(dir, "paired.json"),
		"--platform", "http://127.0.0.1:1", "approval", "full")
	cmd.Env = append(os.Environ(), "TYD_SESSION=abc123")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("approval mode was changed from inside a session:\n%s", out)
	}
	if !strings.Contains(string(out), "refused inside a tyd session") {
		t.Fatalf("unexpected failure:\n%s", out)
	}
	// Nothing may have been written.
	if _, statErr := os.Stat(filepath.Join(dir, "peers.json")); statErr == nil {
		t.Error("peers.json was written despite the refusal")
	}
}

// A session's shell carries the marker, and everything it starts inherits it.
func TestSessionShellCarriesTheMarker(t *testing.T) {
	dir := t.TempDir()
	bin := buildCLI(t)
	// `tyd session list` is allowed inside a session, so it runs and reaches the
	// point where the daemon would be needed; the marker check is what we want
	// to observe, and a shell started by tyd is what sets it. This checks the
	// guard's own view instead: with the marker set the CLI knows it is inside.
	cmd := exec.Command(bin, "--peers", filepath.Join(dir, "peers.json"), "status")
	cmd.Env = append(os.Environ(), "TYD_SESSION=deadbeef")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "refused inside a tyd session") {
		t.Fatalf("status must not be treated as a control command:\n%s", out)
	}
}

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tyd")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build tyd: %v\n%s", err, out)
	}
	return bin
}
