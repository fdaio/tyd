package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/archive"
	"tyd/internal/catalog"
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
	// daemon. The wiring itself — that a real call reaches this — is proved in the
	// remote tests, where a session is driven over a real transport.
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
	f, err := archive.Load(opts.archive)
	if err != nil {
		t.Fatal(err)
	}
	if !f.SessionArchived("1111111111111111") {
		t.Fatal("the closed session past the TTL must be archived by this server's read")
	}
	if f.SessionArchived("2222222222222222") {
		t.Fatal("a running session must not be archived")
	}
}

// A peer's use clock lives beside its archive mark rather than in peers.json,
// because peers.json is rebuilt from the Control Panel and a clock lost there
// would archive a peer in daily use on the strength of its pairing date. A
// server that drives a peer has to move that clock, or the peer is archived
// while the model is typing into it.
func TestDrivingAPeerStopsItBeingArchived(t *testing.T) {
	opts := archiveOpts(t)
	const id = "0123456789abcdef"
	seedPeer(t, opts, id, "box", time.Now().UTC().Add(-30*24*time.Hour))
	pruneArchive(opts)
	if len(archivedPeers(t, opts)) != 1 {
		t.Fatal("a peer paired 30 days ago and never dialled must be archived")
	}

	// What a successful send or read on that target does.
	markUsed(opts, id, "")

	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("dialling a peer must put it back, still archived: %v", got)
	}
	// And the clock is what keeps it out, so the next prune leaves it alone.
	pruneArchive(opts)
	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("a peer in use was archived again at once: %v", got)
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

// The archive hides a session from the list. It does not make the session
// unreachable, and the CLI is where that has to hold: hiding a row an operator
// then cannot attach to would be a way to lose a session. The catalog still
// holds the record and the endpoint, so every command that takes a reference
// resolves it exactly as before.
func TestAnArchivedSessionIsStillReachableByTheDialCommands(t *testing.T) {
	const sid = "0123456789abcdef"
	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"by id", sid},
		{"by alias", "work"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := archiveOpts(t)
			// Seeded with an endpoint, because the endpoint is what a dial
			// command needs and what hiding a row must not take away.
			cat, err := catalog.Load(opts.sessions)
			if err != nil {
				t.Fatal(err)
			}
			cat.Sessions = append(cat.Sessions, catalog.Record{
				ID: sid, State: string(session.StateDetached), Addr: "127.0.0.1:61211",
				Transport: "tls", UpdatedAt: time.Now().UTC(),
			})
			if err := catalog.Save(opts.sessions, cat); err != nil {
				t.Fatal(err)
			}
			adoc := &alias.File{}
			if err := adoc.Set("work", sid, ""); err != nil {
				t.Fatal(err)
			}
			if err := alias.Save(opts.aliases, adoc); err != nil {
				t.Fatal(err)
			}
			markArchived(t, opts, sid)

			// The catalog read every dial command goes through still resolves the
			// reference and still yields the record.
			got, err := resolveSessionRef(opts, tc.ref)
			if err != nil {
				t.Fatal(err)
			}
			if got != sid {
				t.Fatalf("resolveSessionRef = %q, want %q", got, sid)
			}
			rec, ok := loadLocalCatalog(opts).Get(got)
			if !ok {
				t.Fatal("an archived session is gone from the catalog")
			}
			if rec.Addr == "" {
				t.Fatal("an archived session lost the endpoint the dial commands need")
			}
			if ep, ok := endpointFromRecord(rec); !ok || ep.Address != rec.Addr {
				t.Fatalf("the dial endpoint is gone: %+v", rec)
			}
		})
	}
}

// Opening under a name an archived session already holds moves the name, and the
// archived row keeps its id. That is the same rule as opening under the name of
// a live session, so it is defined rather than accidental: one name, one
// session, and the older row still reachable by id.
func TestOpenUnderAnArchivedSessionsNameIsDefined(t *testing.T) {
	const (
		old   = "1111111111111111"
		fresh = "2222222222222222"
	)
	opts := archiveOpts(t)
	seedSession(t, opts, old, "", session.StateClosed, time.Now().UTC().Add(-30*24*time.Hour))
	adoc := &alias.File{}
	if err := adoc.Set("build", old, ""); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(opts.aliases, adoc); err != nil {
		t.Fatal(err)
	}
	markArchived(t, opts, old)

	// What the alias file does when a new session claims the name.
	again := &alias.File{}
	if err := again.Set("build", fresh, ""); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(opts.aliases, again); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSessionRef(opts, "build")
	if err != nil {
		t.Fatal(err)
	}
	if got != fresh {
		t.Fatalf("the alias points at %q, want the session that claimed it", got)
	}
	// And the archived row is still there under its own id.
	if _, ok := loadLocalCatalog(opts).Get(old); !ok {
		t.Fatal("the archived row must survive losing its name")
	}
}
