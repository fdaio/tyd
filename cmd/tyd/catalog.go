package main

import (
	"fmt"
	"strings"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/paths"
	"tyd/internal/recent"
)

// rememberPeerSession records the session a peer command last used, so a bare
// `tyd session attach` can reuse it. attach/watch/close resolve the reference
// before the daemon is consulted, so it can still be a nickname the user typed.
// Remembering that would put a name in recent.json, and the next catalog read
// would turn it into a session row. The dial still goes ahead — a session can
// exist on the daemon without being here — but a name is not worth remembering.
func rememberPeerSession(opts options, peerID, sessionID string) {
	if sessionID != "" && !catalog.IsSessionID(sessionID) {
		sessionID = ""
	}
	// Remember keeps the stored session when the peer is unchanged, so a name
	// already in the file would be written straight back. Clear it first.
	if cur, _ := recent.Load(opts.recent); cur != nil && cur.SessionID != "" && !catalog.IsSessionID(cur.SessionID) {
		cur.SessionID = ""
		_ = recent.Save(opts.recent, cur)
	}
	_ = recent.Remember(opts.recent, peerID, sessionID)
}

func sessionsPath(opts options) string {
	if opts.sessions != "" {
		return opts.sessions
	}
	return paths.DefaultSessions()
}

func loadLocalCatalog(opts options) *catalog.File {
	path := sessionsPath(opts)
	f, err := catalog.Load(path)
	if err != nil {
		f = &catalog.File{}
	}
	n := len(f.Sessions)
	adoc, _ := alias.Load(opts.aliases)

	// Two independent prunes; both must run, so they cannot be chained.
	prunedNames := f.PruneAliasNamedIDs(adoc)
	prunedIDs := f.PruneNonSessionIDs()
	if adoc != nil && adoc.DropCorrupt() {
		_ = alias.Save(opts.aliases, adoc)
	}
	f.MergeAliases(adoc)
	rec, _ := recent.Load(opts.recent)
	if dropUnusableRecent(opts, rec) {
		prunedIDs = true
	}
	f.MergeRecent(rec)
	if f.BackfillCreated() {
		n = -1
	}
	if prunedNames || prunedIDs || len(f.Sessions) != n {
		_ = catalog.Save(path, f)
	}
	return f
}

// dropUnusableRecent clears a recent.json that points at something no daemon
// could have minted. Left alone, a bare `tyd session attach` would keep trying
// to reach a session that does not exist.
func dropUnusableRecent(opts options, rec *recent.File) bool {
	if rec == nil || rec.SessionID == "" || catalog.IsSessionID(rec.SessionID) {
		return false
	}
	rec.SessionID = ""
	return recent.Save(opts.recent, rec) == nil
}

func rememberSession(opts options, rec catalog.Record) {
	_ = catalog.Remember(sessionsPath(opts), rec)
}

// resolveSessionRef maps alias → session id, or uses recent session when ref is empty.
func resolveSessionRef(opts options, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = recent.SessionPlaceholder(opts.recent)
		if ref == "" {
			return "", fmt.Errorf("session id required (no recent session; pass <session_id|alias>)")
		}
	}
	doc, err := alias.Load(opts.aliases)
	if err != nil {
		return "", err
	}
	return doc.Resolve(ref), nil
}

// resolveSessionIDForAlias resolves ref to a session id that must already exist
// in the local catalog (or recent.json). Unlike resolveSessionRef, unknown
// tokens are rejected so an alias name cannot be stored as a session id.
func resolveSessionIDForAlias(opts options, ref string) (string, error) {
	sid, err := resolveSessionRef(opts, ref)
	if err != nil {
		return "", err
	}
	cat := loadLocalCatalog(opts)
	if _, ok := cat.Get(sid); ok {
		return sid, nil
	}
	if rec, _ := recent.Load(opts.recent); rec != nil && rec.SessionID == sid {
		return sid, nil
	}
	if ref == "" {
		return "", fmt.Errorf("recent session %q is not in the local catalog; create/attach it first or pass an explicit session id", sid)
	}
	return "", fmt.Errorf("unknown session %q (not in local catalog)", ref)
}

func validateAliasNameAgainstCatalog(opts options, name string) error {
	name = strings.TrimSpace(name)
	cat := loadLocalCatalog(opts)
	if _, ok := cat.Get(name); ok {
		return fmt.Errorf("alias %q conflicts with an existing session id", name)
	}
	return nil
}
