package recent

import (
	"path/filepath"
	"testing"
)

func TestRememberAndPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recent.json")
	if SessionPlaceholder(path) != "" {
		t.Fatal("empty file should have no placeholder")
	}
	if err := Remember(path, "peer1", "sess1"); err != nil {
		t.Fatal(err)
	}
	if SessionPlaceholder(path) != "sess1" {
		t.Fatalf("got %q", SessionPlaceholder(path))
	}
	// list-style remember preserves session for same peer
	if err := Remember(path, "peer1", ""); err != nil {
		t.Fatal(err)
	}
	if SessionPlaceholder(path) != "sess1" {
		t.Fatalf("preserved got %q", SessionPlaceholder(path))
	}
	// local session with empty peer
	if err := Remember(path, "", "local-sess"); err != nil {
		t.Fatal(err)
	}
	if SessionPlaceholder(path) != "local-sess" {
		t.Fatalf("local got %q", SessionPlaceholder(path))
	}
}
