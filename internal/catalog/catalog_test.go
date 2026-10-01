package catalog

import (
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/protocol"
	"tyd/internal/recent"
)

func TestRememberAndList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	info := protocol.SessionInfo{ID: "abc", State: "DETACHED", PID: 1, CreatedAt: "t"}
	if err := Remember(path, FromInfo(info, "peer1", "10.0.0.1:1", "fp", "tls", nil)); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	list := f.List()
	if len(list) != 1 || list[0].ID != "abc" || list[0].Addr != "10.0.0.1:1" {
		t.Fatalf("%+v", list)
	}
}

func TestMergeAliasesAndRecent(t *testing.T) {
	f := &File{}
	adoc := &alias.File{Aliases: []alias.Entry{{Name: "amy", SessionID: "fedcba9876543210", PeerID: "p1", SetAt: time.Now()}}}
	f.MergeAliases(adoc)
	f.MergeRecent(&recent.File{PeerID: "p1", SessionID: "fedcba9876543210"})
	f.MergeRecent(&recent.File{PeerID: "p2", SessionID: "0011223344556677"})
	if len(f.Sessions) != 2 {
		t.Fatalf("%+v", f.Sessions)
	}
	rec, ok := f.Get("fedcba9876543210")
	if !ok || rec.PeerID != "p1" {
		t.Fatalf("%v %+v", ok, rec)
	}
}

// A nickname reaches recent.json and aliases.json whenever the user types one,
// because the reference is resolved before the daemon is asked. Neither file
// may turn that name into a session row.
func TestMergeSkipsNamesAsSessionIDs(t *testing.T) {
	f := &File{}
	adoc := &alias.File{Aliases: []alias.Entry{
		{Name: "tama.cp", SessionID: "work-laptop", PeerID: "p1"},
		{Name: "ok", SessionID: "0123456789abcdef", PeerID: "p1"},
	}}
	f.MergeAliases(adoc)
	f.MergeRecent(&recent.File{PeerID: "p1", SessionID: "amy"})
	if _, ok := f.Get("work-laptop"); ok {
		t.Error("an alias name must not become a session row")
	}
	if _, ok := f.Get("amy"); ok {
		t.Error("a recent name must not become a session row")
	}
	if _, ok := f.Get("0123456789abcdef"); !ok {
		t.Error("a real session id must still merge")
	}
}

func TestMergeAliasesSkipsCorruptAliasAsID(t *testing.T) {
	f := &File{Sessions: []Record{{ID: "fedcba9876543210", State: "DETACHED"}}}
	adoc := &alias.File{Aliases: []alias.Entry{
		{Name: "tama", SessionID: "tama", PeerID: "p1"},
		{Name: "ok", SessionID: "fedcba9876543210", PeerID: "p1"},
	}}
	f.MergeAliases(adoc)
	if _, ok := f.Get("tama"); ok {
		t.Fatal("corrupt alias name-as-id must not enter catalog")
	}
	if _, ok := f.Get("fedcba9876543210"); !ok {
		t.Fatal("real session missing")
	}
}

func TestIsSessionID(t *testing.T) {
	for _, id := range []string{"0123456789abcdef", "0000000000000000", "abcdef0123456789"} {
		if !IsSessionID(id) {
			t.Errorf("%q should be a session id", id)
		}
	}
	for _, id := range []string{"", "amy", "work-laptop", "tama.cp", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF", "0123456789abcdeg"} {
		if IsSessionID(id) {
			t.Errorf("%q should not be a session id", id)
		}
	}
}

// A row whose id is a name can never be pruned by name once the alias is
// renamed away, so the shape check has to be its own pass.
func TestPruneNonSessionIDs(t *testing.T) {
	f := &File{Sessions: []Record{
		{ID: "amy", State: "DETACHED"},
		{ID: "work-laptop", State: "DETACHED"},
		{ID: "fedcba9876543210", State: "ATTACHED"},
	}}
	if !f.PruneNonSessionIDs() {
		t.Fatal("expected prune")
	}
	if len(f.Sessions) != 1 || f.Sessions[0].ID != "fedcba9876543210" {
		t.Fatalf("%+v", f.Sessions)
	}
	if f.PruneNonSessionIDs() {
		t.Fatal("second prune should be no-op")
	}
}

func TestPruneAliasNamedIDs(t *testing.T) {
	f := &File{Sessions: []Record{
		{ID: "tama", State: "DETACHED", PeerID: "p1"},
		{ID: "fedcba9876543210", State: "DETACHED", PeerID: "p1"},
	}}
	adoc := &alias.File{Aliases: []alias.Entry{
		{Name: "tama", SessionID: "fedcba9876543210", PeerID: "p1"},
	}}
	if !f.PruneAliasNamedIDs(adoc) {
		t.Fatal("expected prune")
	}
	if len(f.Sessions) != 1 || f.Sessions[0].ID != "fedcba9876543210" {
		t.Fatalf("%+v", f.Sessions)
	}
	if f.PruneAliasNamedIDs(adoc) {
		t.Fatal("second prune should be no-op")
	}
}

func TestClosedSortsLast(t *testing.T) {
	f := &File{Sessions: []Record{
		{ID: "closed", State: "CLOSED", UpdatedAt: time.Now()},
		{ID: "live", State: "DETACHED", UpdatedAt: time.Now()},
	}}
	list := f.List()
	if list[0].ID != "live" || list[1].ID != "closed" {
		t.Fatalf("%+v", list)
	}
}

func TestListNewestCreatedFirstWithinGroup(t *testing.T) {
	f := &File{Sessions: []Record{
		{ID: "old-live", State: "DETACHED", CreatedAt: "2024-01-01T00:00:00Z"},
		{ID: "new-live", State: "DETACHED", CreatedAt: "2024-01-03T00:00:00Z"},
		{ID: "old-closed", State: "CLOSED", CreatedAt: "2024-01-02T00:00:00Z"},
		{ID: "new-closed", State: "CLOSED", CreatedAt: "2024-01-04T00:00:00Z"},
	}}
	list := f.List()
	want := []string{"new-live", "old-live", "new-closed", "old-closed"}
	for i, id := range want {
		if list[i].ID != id {
			t.Fatalf("pos %d: got %s want %s (%+v)", i, list[i].ID, id, list)
		}
	}
}

func TestCreatedDisplayAndBackfill(t *testing.T) {
	ts := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	r := Record{ID: "x", UpdatedAt: ts}
	if got := CreatedDisplay(r); got != "2024-02-03T04:05:06Z" {
		t.Fatalf("display=%s", got)
	}
	r.CreatedAt = "2024-01-01T00:00:00Z"
	if got := CreatedDisplay(r); got != r.CreatedAt {
		t.Fatalf("prefer created_at: %s", got)
	}

	f := &File{Sessions: []Record{{ID: "a", UpdatedAt: ts}}}
	if !f.BackfillCreated() || f.Sessions[0].CreatedAt != "2024-02-03T04:05:06Z" {
		t.Fatalf("%+v", f.Sessions)
	}
	if f.BackfillCreated() {
		t.Fatal("second backfill should be no-op")
	}
}

func TestUpsertStampsCreatedAt(t *testing.T) {
	f := &File{}
	f.Upsert(Record{ID: "n", State: "DETACHED"})
	if f.Sessions[0].CreatedAt == "" {
		t.Fatalf("%+v", f.Sessions[0])
	}
}

// Archiving a finished session measures from when it stopped being worth
// listing, which is the later of the close and the last read. A session closed
// long ago and read yesterday is still in use.
func TestArchiveClock(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if got := (Record{ClosedAt: base, LastUsed: base.Add(-time.Hour)}).ArchiveClock(); !got.Equal(base) {
		t.Fatalf("clock = %s, want the close %s", got, base)
	}
	if got := (Record{ClosedAt: base, LastUsed: base.Add(time.Hour)}).ArchiveClock(); !got.Equal(base.Add(time.Hour)) {
		t.Fatalf("clock = %s, want the later read %s", got, base.Add(time.Hour))
	}
	// A row written before closed_at existed falls back to the last write,
	// which for a closed session is the close.
	if got := (Record{UpdatedAt: base}).ArchiveClock(); !got.Equal(base) {
		t.Fatalf("clock = %s, want the fallback %s", got, base)
	}
	if got := (Record{}).ArchiveClock(); !got.IsZero() {
		t.Fatalf("a row with no clock at all must have none, got %s", got)
	}
}

// An endpoint refresh rebuilds the record from what the dial knew, and has no
// opinion on when the session closed or was last read. Losing those would reset
// the clock archiving measures from.
func TestUpsertKeepsClosedAtAndLastUsed(t *testing.T) {
	closed := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	used := closed.Add(time.Hour)
	f := &File{}
	f.Upsert(Record{ID: "abc", State: "CLOSED", ClosedAt: closed, LastUsed: used})
	f.Upsert(Record{ID: "abc", Addr: "10.0.0.1:1"})
	got, ok := f.Get("abc")
	if !ok {
		t.Fatal("record gone")
	}
	if !got.ClosedAt.Equal(closed) || !got.LastUsed.Equal(used) {
		t.Fatalf("closed_at = %s, last_used = %s", got.ClosedAt, got.LastUsed)
	}
}

func TestRemoveAndRemoveByPeer(t *testing.T) {
	f := &File{Sessions: []Record{
		{ID: "a", PeerID: "p1"},
		{ID: "b", PeerID: "p2"},
		{ID: "c", PeerID: "p1"},
	}}
	if !f.Remove("b") || f.Remove("b") {
		t.Fatal("remove must report whether the row was there")
	}
	if got := f.RemoveByPeer("p1"); got != 2 {
		t.Fatalf("removed %d rows for p1, want 2", got)
	}
	if len(f.Sessions) != 0 {
		t.Fatalf("%+v", f.Sessions)
	}
	if f.RemoveByPeer("") != 0 {
		t.Fatal("an empty peer id must remove nothing")
	}
}

// Ties must break the same way every time. Two sessions created in the same second
// have no other order, and a caller that walks the list cannot then say which one
// it got first if the answer changes between runs or between machines.
func TestListOrderIsStableAcrossCalls(t *testing.T) {
	// Same created_at for both, which is the case sort.Slice leaves to chance.
	f := &File{Sessions: []Record{
		{ID: "sess2", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
		{ID: "sess1", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
	}}
	first := ids(f.List())
	for i := 0; i < 50; i++ {
		if got := ids(f.List()); !equal(got, first) {
			t.Fatalf("order changed between calls: %v then %v", first, got)
		}
	}
	if first[0] != "sess1" {
		t.Errorf("ties broke by id ascending, got %v", first)
	}
}

// A stable sort would also be deterministic here, but sort.Slice is not stable, so
// the tiebreak has to be in the comparison. This pins that the tiebreak is not
// merely luck for two sessions.
func TestListTiebreakDoesNotDependOnInputOrder(t *testing.T) {
	forward := &File{Sessions: []Record{
		{ID: "sess1", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
		{ID: "sess2", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
	}}
	reverse := &File{Sessions: []Record{
		{ID: "sess2", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
		{ID: "sess1", State: "DETACHED", CreatedAt: "2026-10-01T00:00:00Z"},
	}}
	if !equal(ids(forward.List()), ids(reverse.List())) {
		t.Errorf("the input order changed the result: %v vs %v",
			ids(forward.List()), ids(reverse.List()))
	}
}

func ids(rs []Record) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
