package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/archive"
	"tyd/internal/session"
)

// The archive is a display state kept outside sessions.json, because the catalog
// is rebuilt from the Control Panel and from aliases.json. Two things follow for
// this server, and both are behaviour a model can observe.
func TestArchivedSessionsAreHiddenFromListButStillAddressable(t *testing.T) {
	opts := archiveOpts(t)
	const (
		hidden = "1111111111111111"
		shown  = "2222222222222222"
	)
	seedSession(t, opts, hidden, "", session.StateClosed, time.Now().UTC().Add(-30*24*time.Hour))
	seedSession(t, opts, shown, "", session.StateDetached, time.Now().UTC())
	markArchived(t, opts, hidden)

	b := newMCPBackend(opts, testIdentity(t), []mcpTarget{{label: mcpLocalRef}})

	rows, err := b.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Session.ID == hidden {
			t.Fatalf("an archived session must not be listed: %+v", rows)
		}
	}
	if len(rows) != 1 || rows[0].Session.ID != shown {
		t.Fatalf("rows = %+v, want only the session in use", rows)
	}

	// Hidden is not unreachable. A model holding the id from an earlier turn is
	// holding a real session, and refusing it would be a worse answer than
	// showing it.
	sess, err := b.Resolve(t.Context(), hidden, "")
	if err != nil {
		t.Fatalf("an archived session must stay addressable: %v", err)
	}
	if sess.ID != hidden {
		t.Fatalf("session = %+v", sess)
	}
}

// A session that is driven is a session in use, so the mark goes and the row
// comes back to the list. This is what the CLI does after an attach, and a
// server that behaved otherwise would hide a session the model is working in.
func TestDrivingAnArchivedSessionBringsItBack(t *testing.T) {
	opts := archiveOpts(t)
	const sid = "1111111111111111"
	seedSession(t, opts, sid, "", session.StateClosed, time.Now().UTC().Add(-30*24*time.Hour))
	markArchived(t, opts, sid)

	b := newMCPBackend(opts, testIdentity(t), []mcpTarget{{label: mcpLocalRef}})

	// The same bookkeeping a successful send or read does, without standing up a
	// daemon: the point under test is that the list follows the use.
	b.markUsed(mcpTarget{label: mcpLocalRef}, sid)

	f, err := archive.Load(opts.archive)
	if err != nil {
		t.Fatal(err)
	}
	if f.SessionArchived(sid) {
		t.Fatal("a session that was just driven must not stay archived")
	}
	rows, err := b.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Session.ID != sid {
		t.Fatalf("rows = %+v, want the session back in the list", rows)
	}
}

// The archive TTL is enforced on this server's read path too, because that is
// where the catalog is read. A server that never pruned would leave a host with
// a growing list and a TTL that does nothing.
func TestTheArchiveTTLAppliesToThisServer(t *testing.T) {
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	seedSession(t, opts, "1111111111111111", "", session.StateClosed, old)
	seedSession(t, opts, "2222222222222222", "", session.StateDetached, old.Add(-time.Hour))

	b := newMCPBackend(opts, testIdentity(t), []mcpTarget{{label: mcpLocalRef}})
	rows, err := b.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The closed one is now hidden, the running one is untouched: a session
	// somebody may still attach to is never a prune candidate.
	if len(rows) != 1 || rows[0].Session.ID != "2222222222222222" {
		t.Fatalf("rows = %+v, want only the running session", rows)
	}
	// The peer clock moves on use, so the target this server drives is not
	// archived while the model is using it.
	f, err := archive.Load(opts.archive)
	if err != nil {
		t.Fatal(err)
	}
	if f.SessionArchived("2222222222222222") {
		t.Fatal("a running session must not be archived")
	}
}

func markArchived(t *testing.T, opts options, ids ...string) {
	t.Helper()
	if err := archive.Update(opts.archive, func(f *archive.File) bool {
		changed := false
		for _, id := range ids {
			if f.ArchiveSession(id, time.Now().UTC()) {
				changed = true
			}
		}
		return changed
	}); err != nil {
		t.Fatal(err)
	}
}

// testIdentity is a real identity: the backend signs with it, and a fake would
// let a test pass on a path the daemon would refuse.
func testIdentity(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	dir := t.TempDir()
	key, err := ensureIdentity(options{
		identity: filepath.Join(dir, "id_ed25519"),
		trust:    filepath.Join(dir, "trusted.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}
