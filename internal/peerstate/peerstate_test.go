package peerstate

import (
	"os"
	"path/filepath"
	"testing"

	"tyd/internal/peers"
)

func writeDoc(t *testing.T, path string, doc *peers.File) {
	t.Helper()
	if err := peers.Save(path, doc); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndSnapshotIsACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	writeDoc(t, path, &peers.File{
		Platform:     "http://cp",
		Registration: &peers.Registration{ID: "d1", PublicKey: "pk", ApprovalMode: "pre"},
		Peers:        []peers.Peer{{ID: "p1", PublicKey: "pk1"}},
	})
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	snap.Registration.ID = "tampered"
	snap.Peers[0].ID = "tampered"
	if reg, _ := s.Registration(); reg.ID != "d1" {
		t.Fatalf("snapshot leaked into state: %s", reg.ID)
	}
	if got := s.Snapshot().Peers[0].ID; got != "p1" {
		t.Fatalf("peer leaked: %s", got)
	}
	if got := s.ApprovalMode("full"); got != "pre" {
		t.Fatalf("approval=%s", got)
	}
	if got := s.Platform("fallback"); got != "http://cp" {
		t.Fatalf("platform=%s", got)
	}
}

func TestMissingFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasRegistration() {
		t.Fatal("empty state must have no registration")
	}
	if got := s.ApprovalMode("full"); got != "full" {
		t.Fatalf("approval=%s", got)
	}
}

func TestCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte(`{"broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("corrupt file should not load silently")
	}
}

// A write that fails must not lose the change: memory keeps it and a later
// Flush puts it on disk.
func TestUpdateKeepsMemoryWhenDiskFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	s := New(path, nil)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	err := s.Update(func(doc *peers.File) {
		doc.Registration = &peers.Registration{ID: "d1", PublicKey: "pk", ApprovalMode: "pre"}
	})
	if err == nil {
		t.Fatal("write into a read-only directory should report an error")
	}
	if reg, ok := s.Registration(); !ok || reg.ID != "d1" {
		t.Fatalf("memory lost the change: %+v", reg)
	}
	if !s.Dirty() {
		t.Fatal("state should be marked dirty")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if s.Dirty() {
		t.Fatal("flush should clear dirty")
	}
	reloaded, err := peers.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Registration == nil || reloaded.Registration.ID != "d1" {
		t.Fatalf("disk missing the change: %+v", reloaded.Registration)
	}
}

func TestReloadIfSane(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	writeDoc(t, path, &peers.File{Registration: &peers.Registration{ID: "d1", PublicKey: "pk"}})
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// A CLI command adds a peer while the daemon runs.
	writeDoc(t, path, &peers.File{
		Registration: &peers.Registration{ID: "d1", PublicKey: "pk"},
		Peers:        []peers.Peer{{ID: "p1", PublicKey: "pk1"}},
	})
	if !s.ReloadIfSane() {
		t.Fatal("a parsable file should be adopted")
	}
	if got := len(s.Snapshot().Peers); got != 1 {
		t.Fatalf("peers=%d", got)
	}

	// The file then gets truncated: memory must win.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if s.ReloadIfSane() {
		t.Fatal("a damaged file must not be adopted")
	}
	if got := len(s.Snapshot().Peers); got != 1 {
		t.Fatalf("memory lost peers after bad reload: %d", got)
	}
	if reg, ok := s.Registration(); !ok || reg.ID != "d1" {
		t.Fatalf("memory lost registration: %+v", reg)
	}
}

// Unsaved memory must not be overwritten by whatever is on disk.
func TestReloadSkippedWhileDirty(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	writeDoc(t, path, &peers.File{Registration: &peers.Registration{ID: "old", PublicKey: "pk"}})
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_ = s.Update(func(doc *peers.File) { doc.Registration.ID = "new" })

	if s.ReloadIfSane() {
		t.Fatal("dirty state must not be replaced from disk")
	}
	if reg, _ := s.Registration(); reg.ID != "new" {
		t.Fatalf("id=%s", reg.ID)
	}
}
