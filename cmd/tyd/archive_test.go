package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/alias"
	"tyd/internal/archive"
	"tyd/internal/catalog"
	"tyd/internal/peers"
	"tyd/internal/recent"
	"tyd/internal/session"
)

// archiveOpts is a client whose whole state lives in one temp directory, so a
// test can read the files the commands wrote.
func archiveOpts(t *testing.T) options {
	t.Helper()
	dir := t.TempDir()
	return options{
		peers:      filepath.Join(dir, "peers.json"),
		paired:     filepath.Join(dir, "paired.json"),
		sessions:   filepath.Join(dir, "sessions.json"),
		aliases:    filepath.Join(dir, "aliases.json"),
		recent:     filepath.Join(dir, "recent.json"),
		archive:    filepath.Join(dir, "archive.json"),
		archiveTTL: DefaultArchiveTTL,
	}
}

func seedPeer(t *testing.T, opts options, id, nick string, pairedAt time.Time) {
	t.Helper()
	doc, err := peers.Load(opts.peers)
	if err != nil {
		t.Fatal(err)
	}
	doc.UpsertPeer(peers.Peer{ID: id, Nickname: nick, PairedAt: pairedAt, PublicKey: "pk-" + id})
	if err := peers.Save(opts.peers, doc); err != nil {
		t.Fatal(err)
	}
}

func seedSession(t *testing.T, opts options, id, peerID string, state session.State, closedAt time.Time) {
	t.Helper()
	cat, err := catalog.Load(opts.sessions)
	if err != nil {
		t.Fatal(err)
	}
	cat.Sessions = append(cat.Sessions, catalog.Record{
		ID:        id,
		PeerID:    peerID,
		State:     string(state),
		ClosedAt:  closedAt,
		UpdatedAt: closedAt,
	})
	if err := catalog.Save(opts.sessions, cat); err != nil {
		t.Fatal(err)
	}
}

func archivedPeers(t *testing.T, opts options) []string {
	t.Helper()
	f, err := archive.Load(opts.archive)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for id := range f.Peers {
		if f.PeerArchived(id) {
			out = append(out, id)
		}
	}
	return out
}

func archivedSessions(t *testing.T, opts options) []string {
	t.Helper()
	f, err := archive.Load(opts.archive)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for id := range f.Sessions {
		if f.SessionArchived(id) {
			out = append(out, id)
		}
	}
	return out
}

// At exactly the TTL the thing has been unused for the full period, so it goes.
// One second short of it and it stays: the boundary decides when a session
// disappears, and it must not land a second early.
func TestPruneArchivesExactlyAtTheBoundary(t *testing.T) {
	opts := archiveOpts(t)
	now := time.Now().UTC()
	seedPeer(t, opts, "atlimit", "", now.Add(-DefaultArchiveTTL))
	seedPeer(t, opts, "justshort", "", now.Add(-DefaultArchiveTTL+time.Second))
	seedPeer(t, opts, "recent", "", now.Add(-time.Minute))
	seedSession(t, opts, "0123456789abcdef", "", session.StateClosed, now.Add(-DefaultArchiveTTL))
	seedSession(t, opts, "fedcba9876543210", "", session.StateClosed, now.Add(-DefaultArchiveTTL+time.Second))

	pruneArchive(opts)

	got := archivedPeers(t, opts)
	if len(got) != 1 || got[0] != "atlimit" {
		t.Fatalf("archived peers = %v, want [atlimit]", got)
	}
	gotSessions := archivedSessions(t, opts)
	if len(gotSessions) != 1 || gotSessions[0] != "0123456789abcdef" {
		t.Fatalf("archived sessions = %v, want [0123456789abcdef]", gotSessions)
	}
}

// Only a finished session is a candidate. PENDING needs an operator, and
// EXITED is a live session whose shell ended and can be attached again.
func TestPruneNeverArchivesAnUnfinishedSession(t *testing.T) {
	opts := archiveOpts(t)
	long := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for i, state := range []session.State{
		session.StatePending,
		session.StateAttached,
		session.StateDetached,
		session.StateExited,
	} {
		seedSession(t, opts, sessionIDForTest(i), "", state, long)
	}
	pruneArchive(opts)
	if got := archivedSessions(t, opts); len(got) != 0 {
		t.Fatalf("archived %v; only CLOSED may be archived", got)
	}
}

func sessionIDForTest(i int) string {
	return string([]byte{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', byte('0' + i),
	})
}

func TestArchiveTTLOffDisablesPruning(t *testing.T) {
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-365 * 24 * time.Hour)
	seedPeer(t, opts, "ancient", "", old)
	seedSession(t, opts, "0123456789abcdef", "", session.StateClosed, old)

	opts.archiveTTL = 0
	pruneArchive(opts)
	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("off must archive nothing, got %v", got)
	}
	if got := archivedSessions(t, opts); len(got) != 0 {
		t.Fatalf("off must archive nothing, got %v", got)
	}
	// off must not even create the file: a host that never archives should not
	// find an archive.json waiting for it.
	if _, err := os.Stat(opts.archive); !os.IsNotExist(err) {
		t.Fatalf("archive file created while archiving is off: %v", err)
	}
}

func TestParseArchiveTTL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"7d", 7 * 24 * time.Hour},
		{"168h", 168 * time.Hour},
		{"1d", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"off", 0},
		{"OFF", 0},
		{"none", 0},
		{"0", 0},
		{"", 0},
	} {
		got, err := parseArchiveTTL(tc.in)
		if err != nil {
			t.Fatalf("parseArchiveTTL(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseArchiveTTL(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// 7days is not accepted: Go spells days in hours, and one spelling of a
	// unit is enough.
	_, err := parseArchiveTTL("7days")
	if err == nil {
		t.Fatal("7days must be rejected")
	}
	for _, want := range []string{"7d", "168h", "off"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must list %q: %v", want, err)
		}
	}
	if _, err := parseArchiveTTL("-1d"); err == nil {
		t.Fatal("a negative TTL must be rejected")
	}
}

func TestArchiveTTLEnvAppliesWhenTheFlagIsAbsent(t *testing.T) {
	t.Setenv(ArchiveTTLEnv, "off")
	opts, err := parseArgs([]string{"session", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.archiveTTL != 0 {
		t.Fatalf("env must switch archiving off, got %s", opts.archiveTTL)
	}

	// The flag is a decision about this command, so it wins over the host.
	opts, err = parseArgs([]string{"--archive-ttl", "3d", "session", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.archiveTTL != 3*24*time.Hour {
		t.Fatalf("flag must win over env, got %s", opts.archiveTTL)
	}
}

func TestArchiveTTLDefaultsToSevenDays(t *testing.T) {
	opts, err := parseArgs([]string{"session", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.archiveTTL != DefaultArchiveTTL {
		t.Fatalf("default = %s, want %s", opts.archiveTTL, DefaultArchiveTTL)
	}
}

func TestPeerListHidesArchivedAndSaysHowMany(t *testing.T) {
	opts := archiveOpts(t)
	now := time.Now().UTC()
	seedPeer(t, opts, "keep", "laptop", now)
	seedPeer(t, opts, "gone", "osaka", now.Add(-30*24*time.Hour))
	// The clock is the last dial, not the pairing, so a peer paired long ago and
	// used yesterday stays listed.
	seedPeer(t, opts, "dialed", "taipei", now.Add(-30*24*time.Hour))
	if err := archive.Update(opts.archive, func(f *archive.File) bool {
		return f.TouchPeer("dialed", now.Add(-24*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}

	list := func(all bool) (string, string) {
		t.Helper()
		var err error
		var out, errOut string
		o := opts
		o.all = all
		out = captureStdout(t, func() {
			errOut = captureStderr(t, func() { err = run(withRest(o, "peer", "list")) })
		})
		if err != nil {
			t.Fatal(err)
		}
		return out, errOut
	}

	out, errOut := list(false)
	if strings.Contains(out, "gone") {
		t.Fatalf("archived peer still listed:\n%s", out)
	}
	// A peer paired long ago and dialled yesterday is in use, so the dial clock
	// has to win over the pairing date.
	if !strings.Contains(out, "keep") || !strings.Contains(out, "laptop") || !strings.Contains(out, "dialed") {
		t.Fatalf("listed peer missing:\n%s", out)
	}
	if !strings.Contains(errOut, "1 archived peer") || !strings.Contains(errOut, "--all") {
		t.Fatalf("footer must count the hidden peer and name the flag: %q", errOut)
	}

	out, errOut = list(true)
	for _, want := range []string{"keep", "gone", "dialed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--all must show %s:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "archived") {
		t.Fatalf("--all must mark the archived row:\n%s", out)
	}
	if strings.Contains(errOut, "archived peer") {
		t.Fatalf("--all shows everything, so nothing is hidden: %q", errOut)
	}
}

func TestSessionListHidesArchivedAndSaysHowMany(t *testing.T) {
	opts := archiveOpts(t)
	now := time.Now().UTC()
	seedSession(t, opts, "0123456789abcdef", "", session.StateClosed, now.Add(-30*24*time.Hour))
	seedSession(t, opts, "fedcba9876543210", "", session.StateDetached, now)

	var err error
	var out, errOut string
	out = captureStdout(t, func() {
		errOut = captureStderr(t, func() { err = run(withRest(opts, "session", "list")) })
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "0123456789abcdef") {
		t.Fatalf("archived session still listed:\n%s", out)
	}
	if !strings.Contains(out, "fedcba9876543210") {
		t.Fatalf("live session missing:\n%s", out)
	}
	if !strings.Contains(errOut, "1 archived session") || !strings.Contains(errOut, "--all") {
		t.Fatalf("footer must count the hidden session and name the flag: %q", errOut)
	}

	o := opts
	o.all = true
	out = captureStdout(t, func() {
		errOut = captureStderr(t, func() { err = run(withRest(o, "session", "list")) })
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "0123456789abcdef") || !strings.Contains(out, "CLOSED (archived)") {
		t.Fatalf("--all must show the archived session and mark it:\n%s", out)
	}
	if strings.Contains(errOut, "archived session") {
		t.Fatalf("--all shows everything, so nothing is hidden: %q", errOut)
	}
}

// Archiving hides a peer; it must not take the peer away. An explicit --peer
// still resolves, and using it puts the peer back in the list.
func TestArchivedPeerStillDialsAndComesBack(t *testing.T) {
	opts := archiveOpts(t)
	const id = "8a6592c332eba2b2"
	seedPeer(t, opts, id, "osaka", time.Now().UTC().Add(-30*24*time.Hour))
	if err := archive.Update(opts.archive, func(f *archive.File) bool {
		return f.ArchivePeer(id, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	// The trust store is untouched: archiving grants and withdraws nothing.
	paired, err := peers.LoadPaired(opts.paired)
	if err != nil {
		t.Fatal(err)
	}
	paired.Upsert(peers.PairedPeer{ID: id, PublicKey: "pk-" + id, PairedAt: time.Now().UTC()})
	if err := peers.SavePaired(opts.paired, paired); err != nil {
		t.Fatal(err)
	}

	byID, _, err := resolvePeerTarget(withPeer(opts, id))
	if err != nil || byID != id {
		t.Fatalf("an archived peer must still resolve by id: %q, %v", byID, err)
	}
	byNick, _, err := resolvePeerTarget(withPeer(opts, "osaka"))
	if err != nil || byNick != id {
		t.Fatalf("an archived peer must still resolve by nickname: %q, %v", byNick, err)
	}

	markUsed(opts, id, "")
	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("dialling the peer must put it back, still archived: %v", got)
	}
}

func withPeer(opts options, peer string) options {
	opts.peer = peer
	return opts
}

func TestRestoreRoundTrip(t *testing.T) {
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	seedPeer(t, opts, "0123456789abcdef", "osaka", old)
	seedSession(t, opts, "fedcba9876543210", "0123456789abcdef", session.StateClosed, old)
	pruneArchive(opts)

	if len(archivedPeers(t, opts)) != 1 || len(archivedSessions(t, opts)) != 1 {
		t.Fatalf("setup: %v %v", archivedPeers(t, opts), archivedSessions(t, opts))
	}

	restore := func(o options) {
		t.Helper()
		if err := run(o); err != nil {
			t.Fatal(err)
		}
	}
	restore(withRest(opts, "peer", "restore", "osaka"))
	restore(withRest(opts, "session", "restore", "fedcba9876543210"))

	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("peer still archived: %v", got)
	}
	if got := archivedSessions(t, opts); len(got) != 0 {
		t.Fatalf("session still archived: %v", got)
	}
	// A restored peer must survive the next prune, or restoring it is a
	// one-command gesture that undoes itself.
	pruneArchive(opts)
	if got := archivedPeers(t, opts); len(got) != 0 {
		t.Fatalf("a restored peer was archived again at once: %v", got)
	}
	// Same for a session, and it cannot be read to keep itself listed either.
	pruneArchive(opts)
	if got := archivedSessions(t, opts); len(got) != 0 {
		t.Fatalf("a restored session was archived again at once: %v", got)
	}

	// Restoring twice is a mistake, not a silent success.
	if err := run(withRest(opts, "peer", "restore", "osaka")); err == nil {
		t.Fatal("restoring a peer that is not archived must say so")
	}
}

func withRest(opts options, parts ...string) options {
	o := opts
	o.cmd = parts[0]
	o.rest = parts[1:]
	return o
}

// A read-only state directory must not turn a list into a failure. Archiving is
// housekeeping, and a list that cannot archive is still a correct list.
func TestPruneFailureIsSilentAndListStillWorks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	seedPeer(t, opts, "0123456789abcdef", "osaka", old)
	seedSession(t, opts, "fedcba9876543210", "", session.StateClosed, old)

	dir := filepath.Dir(opts.archive)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var err error
	peersOut := captureStdout(t, func() {
		captureStderr(t, func() { err = run(withRest(opts, "peer", "list")) })
	})
	if err != nil {
		t.Fatalf("peer list must still succeed on a read-only state directory: %v", err)
	}
	if !strings.Contains(peersOut, "0123456789abcdef") {
		t.Fatalf("peer must still be listed:\n%s", peersOut)
	}
	sessionsOut := captureStdout(t, func() {
		captureStderr(t, func() { err = run(withRest(opts, "session", "list")) })
	})
	if err != nil {
		t.Fatalf("session list must still succeed on a read-only state directory: %v", err)
	}
	if !strings.Contains(sessionsOut, "fedcba9876543210") {
		t.Fatalf("session must still be listed:\n%s", sessionsOut)
	}
	// Nothing was archived, because nothing could be written.
	if _, statErr := os.Stat(opts.archive); !os.IsNotExist(statErr) {
		t.Fatalf("a failed prune must leave no archive file: %v", statErr)
	}
}

// --verbose is the only place a prune failure is reported: it is the operator
// asking to be told what the command did.
func TestPruneFailureIsReportedUnderVerbose(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	seedPeer(t, opts, "0123456789abcdef", "osaka", old)

	dir := filepath.Dir(opts.archive)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	opts.verbose = true
	var err error
	captureStdout(t, func() {
		errOut := captureStderr(t, func() { err = run(withRest(opts, "peer", "list")) })
		if !strings.Contains(errOut, "archive:") {
			t.Fatalf("--verbose must report the prune failure: %q", errOut)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Two CLI processes reading the catalog at the same moment both prune. Each
// must end up with both marks.
func TestConcurrentPrunesKeepBothMarks(t *testing.T) {
	opts := archiveOpts(t)
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	seedPeer(t, opts, "peer-a", "", old)
	seedPeer(t, opts, "peer-b", "", old)
	seedSession(t, opts, "0123456789abcdef", "", session.StateClosed, old)
	seedSession(t, opts, "fedcba9876543210", "", session.StateClosed, old)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				pruneArchive(opts)
			}
		}()
	}
	wg.Wait()

	if got := archivedPeers(t, opts); len(got) != 2 {
		t.Fatalf("archived peers = %v, want both", got)
	}
	if got := archivedSessions(t, opts); len(got) != 2 {
		t.Fatalf("archived sessions = %v, want both", got)
	}
}

// session rm forgets a session here. The alias has to go with it: the catalog
// rebuilds a row for any alias naming a session id it does not have, so an alias
// left behind would put the session straight back into the list.
func TestSessionRemoveTakesItsAliasAndRecentWithIt(t *testing.T) {
	opts := archiveOpts(t)
	const sid = "0123456789abcdef"
	seedSession(t, opts, sid, "", session.StateClosed, time.Now().UTC())
	adoc := &alias.File{}
	if err := adoc.Set("work", sid, ""); err != nil {
		t.Fatal(err)
	}
	if err := alias.Save(opts.aliases, adoc); err != nil {
		t.Fatal(err)
	}
	if err := recent.Remember(opts.recent, "", sid); err != nil {
		t.Fatal(err)
	}

	// Without --force it refuses and changes nothing.
	err := run(withRest(opts, "session", "rm", sid))
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("rm without --force must refuse, got %v", err)
	}
	if cat, _ := catalog.Load(opts.sessions); len(cat.Sessions) != 1 {
		t.Fatal("a refused rm must not remove anything")
	}

	o := opts
	o.force = true
	if err := run(withRest(o, "session", "rm", "work")); err != nil {
		t.Fatal(err)
	}
	cat, _ := catalog.Load(opts.sessions)
	if len(cat.Sessions) != 0 {
		t.Fatalf("session still in the catalog: %+v", cat.Sessions)
	}
	if got, _ := alias.Load(opts.aliases); len(got.Aliases) != 0 {
		t.Fatalf("alias left behind: %+v", got.Aliases)
	}
	if got, _ := recent.Load(opts.recent); got != nil && got.SessionID != "" {
		t.Fatalf("recent entry left behind: %+v", got)
	}
	// And the next read must not rebuild it.
	if cat := loadLocalCatalog(opts); len(cat.Sessions) != 0 {
		t.Fatalf("the session came back: %+v", cat.Sessions)
	}
}

// A row holds the endpoint, so removing one for a session that is still running
// leaves a session this host can no longer reach. --force does not buy that.
func TestSessionRemoveRefusesALiveSessionEvenWithForce(t *testing.T) {
	opts := archiveOpts(t)
	const sid = "0123456789abcdef"
	seedSession(t, opts, sid, "", session.StateDetached, time.Now().UTC())
	o := opts
	o.force = true
	err := run(withRest(o, "session", "rm", sid))
	if err == nil {
		t.Fatal("rm of a live session must fail")
	}
	if !strings.Contains(err.Error(), "close it first") {
		t.Fatalf("the error must name the way out: %v", err)
	}
	if cat, _ := catalog.Load(opts.sessions); len(cat.Sessions) != 1 {
		t.Fatal("the row must survive a refused rm")
	}
}

func TestSessionRemoveRejectsUnknownSession(t *testing.T) {
	opts := archiveOpts(t)
	o := opts
	o.force = true
	if err := run(withRest(o, "session", "rm", "0123456789abcdef")); err == nil {
		t.Fatal("rm of an unknown session must fail")
	}
}

// Revoking is the only act that takes a peer's access away, so it refuses
// without --force. With it, the trust record goes as well: peers.json is not the
// trust store, and an entry left in paired.json keeps the peer trusted until
// some later sync happens to notice.
func TestRevokeRefusesWithoutForceThenDropsTrustAndSessions(t *testing.T) {
	opts := archiveOpts(t)
	now := time.Now().UTC()
	seedPeer(t, opts, "doomed", "osaka", now)
	seedPeer(t, opts, "kept", "taipei", now)
	paired := &peers.PairedFile{Peers: []peers.PairedPeer{
		{ID: "doomed", PublicKey: "pk-doomed", PairedAt: now},
		{ID: "kept", PublicKey: "pk-kept", PairedAt: now},
	}}
	if err := peers.SavePaired(opts.paired, paired); err != nil {
		t.Fatal(err)
	}
	seedSession(t, opts, "0123456789abcdef", "doomed", session.StateClosed, now)
	seedSession(t, opts, "fedcba9876543210", "kept", session.StateClosed, now)

	revoke := func(o options) error {
		var err error
		captureStdout(t, func() {
			captureStderr(t, func() { err = run(withRest(o, "revoke", "osaka")) })
		})
		return err
	}

	err := revoke(opts)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("revoke without --force must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "1 local session record") {
		t.Fatalf("the refusal must say what goes with the peer: %v", err)
	}
	if doc, _ := peers.Load(opts.peers); len(doc.Peers) != 2 {
		t.Fatal("a refused revoke must not remove the peer")
	}

	o := opts
	o.force = true
	if err := revoke(o); err != nil {
		t.Fatal(err)
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Peers) != 1 || doc.Peers[0].ID != "kept" {
		t.Fatalf("peers after revoke: %+v", doc.Peers)
	}
	after, err := peers.LoadPaired(opts.paired)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Peers) != 1 || after.Peers[0].ID != "kept" {
		t.Fatalf("paired.json after revoke: %+v", after.Peers)
	}
	cat, err := catalog.Load(opts.sessions)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Sessions) != 1 || cat.Sessions[0].ID != "fedcba9876543210" {
		t.Fatalf("sessions after revoke: %+v", cat.Sessions)
	}
}
