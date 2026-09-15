package peers

import (
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
