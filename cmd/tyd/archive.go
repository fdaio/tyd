package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"tyd/internal/archive"
	"tyd/internal/catalog"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/session"
)

const (
	// DefaultArchiveTTL is how long a peer, or a finished session, stays in the
	// default views before it is archived out of them.
	DefaultArchiveTTL = 7 * 24 * time.Hour

	// ArchiveTTLEnv sets the TTL for every command that reads state, so a host
	// can choose one and not pass a flag each time.
	ArchiveTTLEnv = "TYD_ARCHIVE_TTL"
)

// parseArchiveTTL accepts a Go duration, a day count, or off. It rejects
// "7days": Go spells days as hours, and accepting two spellings of the same
// unit would leave room for a third.
func parseArchiveTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "off", "none", "0":
		return 0, nil
	}
	if n, err := strconv.Atoi(strings.TrimSuffix(strings.ToLower(v), "d")); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("--archive-ttl %q: must not be negative", v)
		}
		d := time.Duration(n) * 24 * time.Hour
		if d < 0 {
			return 0, fmt.Errorf("--archive-ttl %q: too large", v)
		}
		return d, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("--archive-ttl %q: use days (7d), a duration (168h), or off", v)
	}
	if d < 0 {
		return 0, fmt.Errorf("--archive-ttl %q: must not be negative", v)
	}
	return d, nil
}

// formatTTL spells a TTL the way the flag accepts it. A whole number of days
// reads as days, because "168h0m0s" is what Go prints for the default and says
// nothing about what the flag takes.
func formatTTL(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}

func archivePath(opts options) string {
	if strings.TrimSpace(opts.archive) != "" {
		return opts.archive
	}
	return paths.Archive()
}

// pruneArchive hides whatever has outlived the TTL. It runs on the read paths,
// so it must never be the reason a command fails: an unwritable state
// directory, a full disk or a lock this process cannot take leaves the views
// exactly as they were. Only --verbose reports it, because a list that failed
// to archive is still a correct list.
//
// It reads the catalog and peers.json directly rather than through
// loadLocalCatalog, which is both a merge of aliases and recent.json and the
// place this is called from.
func pruneArchive(opts options) {
	ttl := opts.archiveTTL
	if ttl <= 0 {
		return
	}
	now := time.Now().UTC()

	cat, err := catalog.Load(sessionsPath(opts))
	if err != nil {
		archiveNote(opts, err)
		return
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		archiveNote(opts, err)
		return
	}

	err = archive.Update(archivePath(opts), func(f *archive.File) bool {
		changed := false
		for _, rec := range cat.Sessions {
			// Only a finished session is a candidate. A pending or running one
			// has someone who may still want it, and EXITED is not finished: the
			// session lives on and can be attached again.
			if !strings.EqualFold(rec.State, string(session.StateClosed)) {
				continue
			}
			if !outlived(rec.ArchiveClock(), now, ttl) {
				continue
			}
			if f.ArchiveSession(rec.ID, now) {
				changed = true
			}
		}
		for _, p := range doc.Peers {
			clock := f.PeerLastUsed(p.ID)
			if clock.IsZero() {
				clock = p.PairedAt
			}
			if !outlived(clock, now, ttl) {
				continue
			}
			if f.ArchivePeer(p.ID, now) {
				changed = true
			}
		}
		return changed
	})
	if err != nil {
		archiveNote(opts, err)
	}
}

// outlived reports whether a clock is at least ttl old. The boundary counts as
// outlived: at exactly ttl the thing has been unused for the full period, and
// waiting for the next tick would archive it late, not early.
func outlived(clock, now time.Time, ttl time.Duration) bool {
	if clock.IsZero() || ttl <= 0 {
		return false
	}
	return !clock.After(now.Add(-ttl))
}

// touchSession stamps the use clock on a session record. Commands that do not
// otherwise write the record call this, so the clock does not depend on each
// command remembering to.
func touchSession(opts options, sessionID string) {
	if sessionID == "" {
		return
	}
	if rec, ok := loadLocalCatalog(opts).Get(sessionID); ok {
		rememberSession(opts, rec)
	}
}

// markUsed puts back whatever a successful use un-archives: the peer that was
// dialled, and the session that was touched. Dialling an archived peer has to
// work, because the operator named it, and a peer that stays reachable must not
// stay hidden.
//
// The use clocks live in two files, so this is not atomic across them. Neither
// is a record of trust, and both are stamped again on the next use, so a
// half-written pair costs one stale clock and nothing more.
func markUsed(opts options, peerID, sessionID string) {
	if peerID == "" && sessionID == "" {
		return
	}
	now := time.Now().UTC()
	err := archive.Update(archivePath(opts), func(f *archive.File) bool {
		changed := false
		if f.TouchPeer(peerID, now) {
			changed = true
		}
		if f.TouchSession(sessionID) {
			changed = true
		}
		return changed
	})
	if err != nil {
		archiveNote(opts, err)
	}
}

func loadArchive(opts options) *archive.File {
	f, err := archive.Load(archivePath(opts))
	if err != nil {
		archiveNote(opts, err)
		return &archive.File{}
	}
	return f
}

// restorePeer puts a peer back in the default views. The dial clock moves with
// it, so a peer the operator asked for is not archived again by the next list.
func restorePeer(opts options, idOrNick string) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	p, err := doc.Find(idOrNick)
	if err != nil {
		return err
	}
	var restored bool
	err = archive.Update(archivePath(opts), func(f *archive.File) bool {
		restored = f.RestorePeer(p.ID, time.Now().UTC())
		return restored
	})
	if err != nil {
		return err
	}
	if !restored {
		return fmt.Errorf("peer %s is not archived", p.ID)
	}
	fmt.Printf("restored peer %s\n", p.ID)
	return nil
}

// restoreSession puts a session back in the default views.
//
// The use clock moves with the mark, for the same reason a restored peer's
// does: an archived session is CLOSED, so reading it again is not something the
// operator can do to keep it listed, and a restore that the next list undid
// would not be a restore.
func restoreSession(opts options, idOrNick string) error {
	sid, err := resolveSessionRef(opts, idOrNick)
	if err != nil {
		return fmt.Errorf("usage: tyd session restore <session_id|alias>: %w", err)
	}
	if _, ok := loadLocalCatalog(opts).Get(sid); !ok {
		return fmt.Errorf("unknown session %q (not in local catalog)", idOrNick)
	}
	// The clock moves before the mark clears. loadLocalCatalog prunes on the way
	// through, and a session whose clock is still the old one is exactly what
	// that prune would archive again.
	touchSession(opts, sid)
	var restored bool
	err = archive.Update(archivePath(opts), func(f *archive.File) bool {
		restored = f.RestoreSession(sid)
		return restored
	})
	if err != nil {
		return err
	}
	if !restored {
		return fmt.Errorf("session %s is not archived", sid)
	}
	fmt.Printf("restored session %s\n", sid)
	return nil
}

func archiveNote(opts options, err error) {
	if err == nil || !opts.verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "tyd: archive: %v\n", err)
}
