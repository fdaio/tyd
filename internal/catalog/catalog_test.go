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
	adoc := &alias.File{Aliases: []alias.Entry{{Name: "amy", SessionID: "s1", PeerID: "p1", SetAt: time.Now()}}}
	f.MergeAliases(adoc)
	f.MergeRecent(&recent.File{PeerID: "p1", SessionID: "s1"})
	f.MergeRecent(&recent.File{PeerID: "p2", SessionID: "s2"})
	if len(f.Sessions) != 2 {
		t.Fatalf("%+v", f.Sessions)
	}
	rec, ok := f.Get("s1")
	if !ok || rec.PeerID != "p1" {
		t.Fatalf("%v %+v", ok, rec)
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
