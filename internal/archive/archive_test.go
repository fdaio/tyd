package archive

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLoadMissingFileIsEmpty(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.PeerArchived("x") || f.SessionArchived("x") {
		t.Fatalf("%+v", f)
	}
}

func TestArchiveAndRestoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC().Truncate(time.Second)

	if err := Update(path, func(f *File) bool { return f.ArchivePeer("p1", now) }); err != nil {
		t.Fatal(err)
	}
	if err := Update(path, func(f *File) bool { return f.ArchiveSession("s1", now) }); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.PeerArchived("p1") || !f.SessionArchived("s1") {
		t.Fatalf("%+v", f)
	}
	if f.PeerArchived("p2") || f.SessionArchived("s2") {
		t.Fatal("a peer that was never archived must not read as archived")
	}

	later := now.Add(time.Hour)
	if err := Update(path, func(f *File) bool { return f.RestorePeer("p1", later) }); err != nil {
		t.Fatal(err)
	}
	if err := Update(path, func(f *File) bool { return f.RestoreSession("s1") }); err != nil {
		t.Fatal(err)
	}
	f, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.PeerArchived("p1") || f.SessionArchived("s1") {
		t.Fatalf("%+v", f)
	}
	// A restored peer must not be archived again by the next prune, which is
	// what its clock is for.
	if got := f.PeerLastUsed("p1"); !got.Equal(later) {
		t.Fatalf("last used = %s, want %s", got, later)
	}
}

// A peer the client dialled again is in use, so a mark left on it would hide
// the peer the operator just reached for.
func TestTouchPeerStampsAndUnarchives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC()
	if err := Update(path, func(f *File) bool { return f.ArchivePeer("p1", now) }); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	if err := Update(path, func(f *File) bool { return f.TouchPeer("p1", later) }); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.PeerArchived("p1") {
		t.Fatal("a peer that was dialled again must not stay archived")
	}
	if got := f.PeerLastUsed("p1"); !got.Equal(later) {
		t.Fatalf("last used = %s, want %s", got, later)
	}
}

func TestTouchSessionUnarchivesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC()
	if err := Update(path, func(f *File) bool { return f.ArchiveSession("s1", now) }); err != nil {
		t.Fatal(err)
	}
	if err := Update(path, func(f *File) bool { return f.TouchSession("s1") }); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.SessionArchived("s1") {
		t.Fatal("a session that was read again must not stay archived")
	}
}

// fn reporting no change must leave the file alone, or a prune that finds
// nothing new would rewrite the file on every single command.
func TestUpdateSkipsWriteWhenNothingChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC()
	if err := Update(path, func(f *File) bool { return f.ArchivePeer("p1", now) }); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	again := now.Add(time.Hour)
	if err := Update(path, func(f *File) bool { return f.ArchivePeer("p1", again) }); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("archiving an already archived peer rewrote the file")
	}
}

// Two tyd processes prune at the same moment. Without the lock around the whole
// read-modify-write, each reads the file, each adds its own mark, and each
// writes back a copy missing the other's.
func TestConcurrentUpdatesKeepBothMarks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC()
	var wg sync.WaitGroup
	for _, id := range []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := Update(path, func(f *File) bool { return f.ArchivePeer(id, now) }); err != nil {
					t.Errorf("archive %s: %v", id, err)
					return
				}
			}
		}(id)
	}
	wg.Wait()
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"} {
		if !f.PeerArchived(id) {
			t.Fatalf("%s was dropped by a concurrent update: %+v", id, f.Peers)
		}
	}
}

func TestForgetDropsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.json")
	now := time.Now().UTC()
	if err := Update(path, func(f *File) bool {
		changed := f.TouchPeer("p1", now)
		if f.ArchiveSession("s1", now) {
			changed = true
		}
		return changed
	}); err != nil {
		t.Fatal(err)
	}
	if err := Update(path, func(f *File) bool {
		changed := f.ForgetPeer("p1")
		if f.ForgetSession("s1") {
			changed = true
		}
		return changed
	}); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.PeerLastUsed("p1").IsZero() == false || f.SessionArchived("s1") {
		t.Fatalf("%+v %+v", f.Peers, f.Sessions)
	}
	if f.ForgetPeer("p1") {
		t.Fatal("forgetting a peer twice must report no change")
	}
}
