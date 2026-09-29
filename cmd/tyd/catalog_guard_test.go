package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/recent"
)

// A nickname typed into `tyd session attach` is written to recent.json before
// the daemon is asked whether it exists. Left alone, the next catalog read
// turns that name into a session row, the row shows up in `tyd session list`,
// and the name can never be used as an alias again.
func TestNameNeverBecomesASession(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
	}

	// A name is still resolved through, and the dial still goes ahead: a
	// session can exist on the daemon without being in the local catalog.
	got, err := resolveSessionRef(opts, "work-laptop")
	if err != nil || got != "work-laptop" {
		t.Fatalf("resolveSessionRef = %q, %v", got, err)
	}

	// What must not happen is the name being remembered.
	rememberPeerSession(opts, "a1b2c3d4e5f60718", "work-laptop")
	rec, _ := recent.Load(opts.recent)
	if rec.SessionID != "" {
		t.Fatalf("a name must not be remembered as a session id, got %q", rec.SessionID)
	}
	// The peer is still worth keeping, so a bare command keeps its endpoint.
	if rec.PeerID != "a1b2c3d4e5f60718" {
		t.Fatalf("peer lost: %+v", rec)
	}

	// A real id is remembered as before.
	rememberPeerSession(opts, "a1b2c3d4e5f60718", "0123456789abcdef")
	rec, _ = recent.Load(opts.recent)
	if rec.SessionID != "0123456789abcdef" {
		t.Fatalf("real session id not remembered: %+v", rec)
	}

	// A recent.json that already holds a name, and a catalog that already
	// holds the resulting row, both heal on the next read.
	if err := recent.Remember(opts.recent, "a1b2c3d4e5f60718", "work-laptop"); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Save(opts.sessions, &catalog.File{Sessions: []catalog.Record{
		{ID: "work-laptop", State: "DETACHED"},
		{ID: "fedcba9876543210", State: "ATTACHED"},
	}}); err != nil {
		t.Fatal(err)
	}
	cat := loadLocalCatalog(opts)
	if _, ok := cat.Get("work-laptop"); ok {
		t.Error("the name row must be gone from the catalog")
	}
	if _, ok := cat.Get("fedcba9876543210"); !ok {
		t.Error("a real row must survive")
	}
	if err := validateAliasNameAgainstCatalog(opts, "work-laptop"); err != nil {
		t.Fatalf("the name must be usable as an alias again: %v", err)
	}
	// The healed catalog is on disk, not just in memory.
	if saved, _ := catalog.Load(opts.sessions); len(saved.Sessions) != 1 {
		t.Fatalf("prune not persisted: %+v", saved.Sessions)
	}
	// So is the healed recent.json, or a bare attach would keep reaching for it.
	rec, _ = recent.Load(opts.recent)
	if rec.SessionID != "" {
		t.Fatalf("recent.json still points at %q", rec.SessionID)
	}
}

// loadLocalCatalog runs two prunes, and a catalog can need both at once: one
// row matches a current alias name, another matches nothing but the wrong
// shape. Chaining the two calls with || lets the short circuit skip the second,
// which is how a name outlives the alias that shadowed it.
func TestBothCatalogPrunesRun(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
	}
	adoc := &alias.File{}
	if err := adoc.Set("tama", "fedcba9876543210", "a1b2c3d4e5f60718"); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(opts.aliases, adoc); err != nil {
		t.Fatal(err)
	}

	if err := catalog.Save(opts.sessions, &catalog.File{Sessions: []catalog.Record{
		{ID: "tama", State: "DETACHED"}, // matches a current alias name
		{ID: "amy", State: "DETACHED"},  // no alias, only the shape is wrong
		{ID: "fedcba9876543210", State: "ATTACHED"},
	}}); err != nil {
		t.Fatal(err)
	}

	cat := loadLocalCatalog(opts)
	for _, gone := range []string{"tama", "amy"} {
		if _, ok := cat.Get(gone); ok {
			t.Errorf("%q should have been pruned", gone)
		}
	}
	if len(cat.Sessions) != 1 {
		t.Fatalf("%+v", cat.Sessions)
	}

	b, err := os.ReadFile(opts.sessions)
	if err != nil {
		t.Fatal(err)
	}
	var f catalog.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Sessions) != 1 || f.Sessions[0].ID != "fedcba9876543210" {
		t.Fatalf("prune not persisted: %+v", f.Sessions)
	}
}

// A name is never a session id, so the refusal a user hits must only ever speak
// about sessions that exist.
func TestAliasConflictNeedsARealSession(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
	}
	if err := catalog.Save(opts.sessions, &catalog.File{Sessions: []catalog.Record{
		{ID: "0123456789abcdef", State: "DETACHED"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := validateAliasNameAgainstCatalog(opts, "0123456789abcdef"); err == nil ||
		!strings.Contains(err.Error(), "conflicts with an existing session id") {
		t.Fatalf("a real session id must still be refused, got %v", err)
	}
	if err := validateAliasNameAgainstCatalog(opts, "work-laptop"); err != nil {
		t.Fatalf("a name must be accepted, got %v", err)
	}
}
