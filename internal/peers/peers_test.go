package peers

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSaveUpsert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Peers) != 0 {
		t.Fatalf("%+v", f)
	}
	f.Platform = "http://127.0.0.1:9"
	f.Registration = &Registration{
		ID:           "abc",
		PublicKey:    "pk",
		ApprovalMode: "full",
		RegisteredAt: time.Now().UTC(),
	}
	f.UpsertPeer(Peer{ID: "peer1", PublicKey: "ppk", Nickname: "lap", PairedAt: time.Now().UTC()})
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Registration == nil || got.Registration.ID != "abc" {
		t.Fatalf("%+v", got.Registration)
	}
	if len(got.Peers) != 1 || got.Peers[0].Nickname != "lap" {
		t.Fatalf("%+v", got.Peers)
	}
	got.UpsertPeer(Peer{ID: "peer1", PublicKey: "ppk", Nickname: "renamed", PairedAt: time.Now().UTC()})
	if len(got.Peers) != 1 || got.Peers[0].Nickname != "renamed" {
		t.Fatalf("upsert %+v", got.Peers)
	}
}

func TestFindAndOutbound(t *testing.T) {
	f := &File{Peers: []Peer{
		{ID: "aaa", PublicKey: "p1", Nickname: "lap", Direction: "outbound"},
		{ID: "bbb", PublicKey: "p2", Direction: "inbound"},
	}}
	p, err := f.Find("lap")
	if err != nil || p.ID != "aaa" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = f.Find("bbb")
	if err != nil || p.ID != "bbb" {
		t.Fatalf("%+v %v", p, err)
	}
	out := f.Outbound()
	if len(out) != 1 || out[0].ID != "aaa" {
		t.Fatalf("%+v", out)
	}
	if !(&File{Registration: &Registration{ID: "x"}}).HasRegistration() {
		t.Fatal("expected registration")
	}
}

func TestReplaceFromRemoteAndRemove(t *testing.T) {
	f := &File{Peers: []Peer{
		{ID: "aaa", PublicKey: "p1", Nickname: "lap", Direction: "outbound"},
		{ID: "bbb", PublicKey: "p2", Direction: "inbound"},
	}}
	f.ReplaceFromRemote([]Peer{{ID: "aaa", PublicKey: "p1", Direction: "outbound"}})
	if len(f.Peers) != 1 || f.Peers[0].Nickname != "lap" {
		t.Fatalf("keep nick %+v", f.Peers)
	}
	if _, err := f.RemovePeer("lap"); err != nil {
		t.Fatal(err)
	}
	if len(f.Peers) != 0 {
		t.Fatalf("%+v", f.Peers)
	}
}

func TestSetAndClearNickname(t *testing.T) {
	f := &File{Peers: []Peer{
		{ID: "aaa", PublicKey: "p1", Nickname: "lap", Direction: "outbound"},
		{ID: "bbb", PublicKey: "p2", Nickname: "box", Direction: "inbound"},
	}}
	if err := f.SetNickname("aaa", "box"); err != nil {
		t.Fatal(err)
	}
	if f.Peers[0].Nickname != "box" {
		t.Fatalf("aaa nick %q", f.Peers[0].Nickname)
	}
	if f.Peers[1].Nickname != "" {
		t.Fatalf("conflicting nick not cleared: %+v", f.Peers[1])
	}
	if err := f.SetNickname("bbb", "bad name"); err == nil {
		t.Fatal("expected whitespace validation error")
	}
	if err := f.ClearNickname("lap"); err == nil {
		t.Fatal("lap nick was moved; expect unknown")
	}
	if err := f.ClearNickname("aaa"); err != nil {
		t.Fatal(err)
	}
	if f.Peers[0].Nickname != "" {
		t.Fatalf("clear failed: %+v", f.Peers[0])
	}
	if err := f.SetNickname("bbb", "desk"); err != nil {
		t.Fatal(err)
	}
	p, err := f.Find("desk")
	if err != nil || p.ID != "bbb" {
		t.Fatalf("%+v %v", p, err)
	}
}

// A save that cannot complete must leave the previous peers.json readable:
// this is what turned a full disk into a daemon that could not talk to the CP.
func TestSaveFailureKeepsPreviousFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	if err := Save(path, &File{
		Registration: &Registration{ID: "d1", PublicKey: "pk", ApprovalMode: "pre"},
		Peers:        []Peer{{ID: "p1", PublicKey: "pk1"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := Save(path, &File{Registration: &Registration{ID: "d2"}}); err == nil {
		t.Fatal("save into a read-only directory should fail")
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("previous file no longer loads: %v", err)
	}
	if got.Registration == nil || got.Registration.ID != "d1" {
		t.Fatalf("registration = %+v", got.Registration)
	}
	if len(got.Peers) != 1 {
		t.Fatalf("peers = %+v", got.Peers)
	}
}

// peer list must read the same way session list does: newest first. The file
// order is the order pairings were written, which is neither.
func TestListOrdersNewestPairingFirst(t *testing.T) {
	base := time.Date(2026, 9, 28, 8, 45, 0, 0, time.UTC)
	f := &File{Peers: []Peer{
		{ID: "oldest", PairedAt: base.Add(-72 * time.Hour)},
		{ID: "newest", PairedAt: base},
		{ID: "middle", PairedAt: base.Add(-24 * time.Hour)},
		{ID: "unpaired", PairedAt: time.Time{}},
	}}

	var got []string
	for _, p := range f.List() {
		got = append(got, p.ID)
	}
	want := []string{"newest", "middle", "oldest", "unpaired"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}

	// Equal timestamps keep file order, matching session list's SliceStable.
	same := base
	tie := &File{Peers: []Peer{
		{ID: "first", PairedAt: same},
		{ID: "second", PairedAt: same},
	}}
	if tie.List()[0].ID != "first" {
		t.Errorf("equal PairedAt should keep file order, got %s first", tie.List()[0].ID)
	}
}

// List must not reorder the file itself: peers.json order is what other code
// reads, and rewriting it on every listing would churn the file.
func TestListDoesNotMutateFile(t *testing.T) {
	f := &File{Peers: []Peer{
		{ID: "a", PairedAt: time.Unix(1, 0)},
		{ID: "b", PairedAt: time.Unix(2, 0)},
	}}
	_ = f.List()
	if f.Peers[0].ID != "a" {
		t.Fatalf("List reordered the file: %s first", f.Peers[0].ID)
	}
	// And the returned slice must be a copy.
	out := f.List()
	out[0].ID = "mutated"
	if f.Peers[0].ID == "mutated" {
		t.Fatal("List returned the live slice, not a copy")
	}
}

// A nickname is rendered into `tyd <alias>.<nickname>`, which tyd asks a person to
// run, so the same rule as an alias applies.
func TestValidateNicknameRefusesAnythingExecutable(t *testing.T) {
	for _, name := range []string{"a`id`", "a$(id)", "a$IFS", "a;id", "a|id", "a>x", "*", "a@b", "a:1"} {
		if err := ValidateNickname(name); err == nil {
			t.Errorf("accepted %q, which substitutes when pasted into a shell", name)
		}
	}
	for _, name := range []string{"laptop", "web-01", "东京", "a.b_c-d"} {
		if err := ValidateNickname(name); err != nil {
			t.Errorf("refused %q: %v", name, err)
		}
	}
	// The reserved name stays reserved.
	if err := ValidateNickname(ReservedNickname); err == nil {
		t.Error("the reserved nickname was accepted")
	}
}
