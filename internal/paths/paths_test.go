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
		want := filepath.Join(os.TempDir(), "tyd.sock")
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}
