package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileCreatesWithPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	if err := WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}\n" {
		t.Fatalf("content %q", b)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm=%o", perm)
	}
}

func TestWriteFileReplacesAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("content %q", b)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%v", entries)
	}
}

// The reason this package exists: a write that cannot complete must not take
// the previous contents with it.
func TestFailedWriteKeepsOldContent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteFile(path, []byte("good"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := WriteFile(path, []byte("bad"), 0o600); err == nil {
		t.Fatal("write into a read-only directory should fail")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "good" {
		t.Fatalf("old content lost: %q", b)
	}
}
