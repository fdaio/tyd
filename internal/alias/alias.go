// Package alias stores client-side session name aliases (not peer nicknames).
package alias

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"tyd/internal/safefile"
)

// File maps alias name -> session id (and optional peer for display).
type File struct {
	Aliases []Entry `json:"aliases"`
}

type Entry struct {
	Name      string    `json:"name"`
	SessionID string    `json:"session_id"`
	PeerID    string    `json:"peer_id,omitempty"`
	SetAt     time.Time `json:"set_at"`
}

func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("aliases file: %w", err)
	}
	if f.Aliases == nil {
		f.Aliases = []Entry{}
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{}
	}
	if f.Aliases == nil {
		f.Aliases = []Entry{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

func ValidateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty alias name")
	}
	if strings.ContainsAny(name, " \t\n/") {
		return fmt.Errorf("alias name must not contain whitespace or '/'")
	}
	if len(name) > 64 {
		return fmt.Errorf("alias name too long")
	}
	return nil
}

// Set binds name to sessionID. Replaces any existing entry with the same name
// or the same session id (one alias per session).
//
// name must not equal sessionID, and must not collide with any other entry's
// session_id (that would make list/resolve treat the alias as a session id).
// sessionID must not equal any other entry's name unless we are replacing that
// alias (caller should pass a real session id, not an alias name as the id).
func (f *File) Set(name, sessionID, peerID string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return fmt.Errorf("empty session id")
	}
	name = strings.TrimSpace(name)
	if name == sessionID {
		return fmt.Errorf("alias %q must differ from the session id", name)
	}
	for _, e := range f.Aliases {
		if e.SessionID == name {
			return fmt.Errorf("alias %q conflicts with session id of existing alias %q", name, e.Name)
		}
		if e.Name == sessionID && e.SessionID != sessionID {
			// sessionID looks like an alias name pointing elsewhere — refuse.
			return fmt.Errorf("%q is an alias for %s; use the session id, not the alias name, as the target", sessionID, e.SessionID)
		}
	}
	out := make([]Entry, 0, len(f.Aliases)+1)
	for _, e := range f.Aliases {
		if e.Name == name || e.SessionID == sessionID {
			continue
		}
		out = append(out, e)
	}
	out = append(out, Entry{
		Name:      name,
		SessionID: sessionID,
		PeerID:    peerID,
		SetAt:     time.Now().UTC(),
	})
	f.Aliases = out
	return nil
}

func (f *File) Remove(name string) error {
	name = strings.TrimSpace(name)
	filtered := f.Aliases[:0]
	found := false
	for _, e := range f.Aliases {
		if e.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !found {
		return fmt.Errorf("unknown alias %q", name)
	}
	f.Aliases = filtered
	return nil
}

// RemoveBySession drops every alias bound to a session id and returns how many
// went. Removing a session has to take its names with it: catalog.MergeAliases
// rebuilds a row for any alias whose session id is missing, so an alias left
// behind would put the session straight back into the list.
func (f *File) RemoveBySession(sessionID string) int {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0
	}
	out := f.Aliases[:0]
	dropped := 0
	for _, e := range f.Aliases {
		if e.SessionID == sessionID {
			dropped++
			continue
		}
		out = append(out, e)
	}
	f.Aliases = out
	return dropped
}

// Resolve returns the session id for a name or session id.
// If ref matches an alias name, returns that session id.
// If ref matches a known session id that has an alias, still returns ref.
// If ref is not an alias, returns ref unchanged (treat as raw session id).
func (f *File) Resolve(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || f == nil {
		return ref
	}
	for _, e := range f.Aliases {
		if e.Name == ref {
			return e.SessionID
		}
	}
	return ref
}

// DropCorrupt removes entries where session_id equals some alias name (or
// equals its own name). Those poison session list via catalog merge.
func (f *File) DropCorrupt() bool {
	if f == nil || len(f.Aliases) == 0 {
		return false
	}
	names := map[string]struct{}{}
	for _, e := range f.Aliases {
		if n := strings.TrimSpace(e.Name); n != "" {
			names[n] = struct{}{}
		}
	}
	out := f.Aliases[:0]
	changed := false
	for _, e := range f.Aliases {
		id := strings.TrimSpace(e.SessionID)
		name := strings.TrimSpace(e.Name)
		if id == "" || name == "" || name == id {
			changed = true
			continue
		}
		if _, bad := names[id]; bad {
			changed = true
			continue
		}
		out = append(out, e)
	}
	f.Aliases = out
	return changed
}

// NameFor returns the alias name for a session id, or empty.
func (f *File) NameFor(sessionID string) string {
	if f == nil {
		return ""
	}
	sessionID = strings.TrimSpace(sessionID)
	for _, e := range f.Aliases {
		if e.SessionID == sessionID {
			return e.Name
		}
	}
	return ""
}
