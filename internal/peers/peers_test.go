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
