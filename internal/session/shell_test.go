package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeShells points the validation at a test file instead of the real
// /etc/shells, which is a property of the host and would make these tests
// pass or fail depending on where they run.
func writeShells(t *testing.T, lines ...string) {
	t.Helper()
	old := shellsFile
	shellsFile = filepath.Join(t.TempDir(), "shells")
	if err := os.WriteFile(shellsFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shellsFile = old })
}

func TestValidateShellAcceptsListedShell(t *testing.T) {
	writeShells(t, "# a comment", "", "/bin/bash", "/bin/zsh")
	if err := validateShell("/bin/zsh"); err != nil {
		t.Fatalf("a listed shell should be accepted, got %v", err)
	}
}

func TestValidateShellRejectsUnlistedShell(t *testing.T) {
	writeShells(t, "/bin/bash")
	err := validateShell("/opt/homebrew/bin/fish")
	if err == nil {
		t.Fatal("an unlisted shell should be rejected")
	}
	// The caller may be on another host, so the message has to name the
	// shell, the file that decides, and what to do about it.
	for _, want := range []string{"/opt/homebrew/bin/fish", shellsFile, "on this host"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message should mention %q, got %q", want, err)
		}
	}
}

// An empty shell means "the daemon's own shell", which must keep working even
// when the file does not list it. Refusing that would be a regression.
func TestValidateShellEmptyIsAllowed(t *testing.T) {
	writeShells(t, "/bin/only-this-one")
	if err := validateShell(""); err != nil {
		t.Fatalf("the default shell must not be gated, got %v", err)
	}
}

// Without the file there is nothing to check against. The requester can
// already run this shell as the default, so the create is not blocked.
func TestValidateShellMissingFileIsAllowed(t *testing.T) {
	old := shellsFile
	shellsFile = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { shellsFile = old })
	if err := validateShell("/bin/bash"); err != nil {
		t.Fatalf("a missing /etc/shells should not block a create, got %v", err)
	}
}

// The whole point of validating on the daemon: a shell that is valid where
// the client runs says nothing about the host that will start the session.
func TestValidateShellIsDecidedByThisHost(t *testing.T) {
	writeShells(t, "/bin/bash")
	if err := validateShell("/bin/bash"); err != nil {
		t.Fatalf("this host lists it, so it must be accepted, got %v", err)
	}
	// A shell the client likes but this host does not list is refused.
	if err := validateShell("/usr/local/bin/nu"); err == nil {
		t.Fatal("a shell absent from this host's list should be refused")
	}
}

func TestCreateRejectsUnlistedShell(t *testing.T) {
	writeShells(t, "/bin/bash")
	m := NewManager()
	if _, err := m.Create(CreateOpts{Shell: "/bin/definitely-not-here"}); err == nil {
		t.Fatal("create should refuse a shell this host does not list")
	}
	m.CloseAll()
}
