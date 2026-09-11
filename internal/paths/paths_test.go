package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSocketUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := DefaultSocket()
	want := filepath.Join(home, ".tyd", "tyd.sock")
	if got != want {
		t.Fatalf("DefaultSocket() = %q, want %q", got, want)
	}
	if DefaultIdentity() != filepath.Join(home, ".tyd", "id_ed25519") {
		t.Fatalf("identity %q", DefaultIdentity())
	}
	if DefaultTrust() != filepath.Join(home, ".tyd", "trusted.json") {
		t.Fatalf("trust %q", DefaultTrust())
	}
}

func TestDefaultSocketFallsBackWhenHomeMissing(t *testing.T) {
	t.Setenv("HOME", "")
	got := DefaultSocket()
	if got == "" {
		t.Fatal("empty socket path")
	}
	if filepath.Base(got) != "tyd.sock" {
		t.Fatalf("got %q, want a tyd.sock path", got)
	}
	if _, err := os.UserHomeDir(); err != nil {
		want := filepath.Join(os.TempDir(), ".tyd", "tyd.sock")
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}
