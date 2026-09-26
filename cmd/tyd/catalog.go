package main

import (
	"fmt"
	"strings"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/paths"
	"tyd/internal/recent"
)

func rememberPeerSession(opts options, peerID, sessionID string) {
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

	pruned := f.PruneAliasNamedIDs(adoc)
	if adoc != nil && adoc.DropCorrupt() {
		_ = alias.Save(opts.aliases, adoc)
	}
	f.MergeAliases(adoc)
	rec, _ := recent.Load(opts.recent)
	f.MergeRecent(rec)
	if f.BackfillCreated() {
		n = -1
	}
	if pruned || len(f.Sessions) != n {
		_ = catalog.Save(path, f)
	}
	return f
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
