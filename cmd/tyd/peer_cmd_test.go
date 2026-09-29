package main

import (
	"bytes"
	"path/filepath"
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

// A dotted nickname parses as two dots in `tyd <session>.<peer>`, so setting
// one says so there and then instead of leaving a usage error for later.
func TestPeerAliasWarnsOnDotName(t *testing.T) {
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.json")
	const id = "8a6592c332eba2b2"
	doc := &peers.File{Peers: []peers.Peer{{ID: id, PairedAt: time.Now().UTC()}}}
	if err := peers.Save(peersPath, doc); err != nil {
		t.Fatal(err)
	}

	namePeer := func(name string) (string, string) {
		t.Helper()
		var err error
		var errOut string
		out := captureStdout(t, func() {
			errOut = captureStderr(t, func() {
				err = run(options{cmd: "peer", rest: []string{"alias", id, name}, peers: peersPath})
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		return out, errOut
	}

	out, errOut := namePeer("osaka.tokyo")
	if !strings.Contains(out, "osaka.tokyo -> "+id) {
		t.Fatalf("nickname line missing: %q", out)
	}
	for _, want := range []string{"osaka.tokyo", "tyd <session>.<peer>", "--peer osaka.tokyo"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("warning missing %q: %q", want, errOut)
		}
	}
	if got, _ := peers.Load(peersPath); got.Peers[0].Nickname != "osaka.tokyo" {
		t.Fatalf("a dotted nickname is still legal and must be stored, got %q", got.Peers[0].Nickname)
	}

	if _, errOut = namePeer("osaka"); errOut != "" {
		t.Fatalf("plain nickname must stay silent: %q", errOut)
	}
}
