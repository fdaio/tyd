package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"tyd/internal/peers"
)

func TestWritePeerShowFieldsLabels(t *testing.T) {
	var buf bytes.Buffer
	writePeerShowFields(&buf, "abc", "amy", "outbound", "2026-09-16T09:53:22Z", "2pwNT1Vzrv7jw+1w…")
	out := buf.String()
	for _, bad := range []string{"paired_at", "public_key"} {
		if strings.Contains(out, bad) {
			t.Fatalf("snake_case label %q in CLI output: %q", bad, out)
		}
	}
	for _, want := range []string{"id:", "alias:", "direction:", "paired:", "public key:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}

// `tyd peer list` must order like `tyd session list`: newest pairing on top.
// The file order is the order pairings were written, so without this the
// newest peer lands wherever it happened to be appended.
func TestPeerListOrdersNewestFirst(t *testing.T) {
	base := time.Date(2026, 9, 28, 8, 45, 0, 0, time.UTC)
	doc := &peers.File{Peers: []peers.Peer{
		{ID: "oldest", PairedAt: base.Add(-72 * time.Hour)},
		{ID: "newest", PairedAt: base, Nickname: "osaka"},
		{ID: "middle", PairedAt: base.Add(-24 * time.Hour)},
	}}

	rows := peerListRows(doc)
	want := []string{"newest", "middle", "oldest"}
	for i, id := range want {
		if rows[i].ID != id {
			t.Fatalf("row %d = %s, want %s (order %v)", i, rows[i].ID, id, rows)
		}
	}
	if rows[0].Alias != "osaka" {
		t.Errorf("newest row alias = %q, want osaka", rows[0].Alias)
	}

	var buf bytes.Buffer
	writePeerList(&buf, rows)
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("want a header and 3 rows, got:\n%s", out)
	}
	if !strings.Contains(lines[0], "ID") || !strings.Contains(lines[0], "PAIRED") {
		t.Errorf("header = %q", lines[0])
	}
	newestAt := strings.Index(out, "newest")
	oldestAt := strings.Index(out, "oldest")
	if newestAt < 0 || oldestAt < 0 || newestAt > oldestAt {
		t.Errorf("newest peer must be printed first:\n%s", out)
	}
	if !strings.Contains(lines[1], "2026-09-28T08:45:00Z") {
		t.Errorf("first row should show the newest PAIRED timestamp: %q", lines[1])
	}
}
