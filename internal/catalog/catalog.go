// Package catalog is the client-side session directory.
// List is a local file read; it never talks to the Control Panel or a daemon.
package catalog

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"tyd/internal/alias"
	"tyd/internal/protocol"
	"tyd/internal/recent"
	"tyd/internal/safefile"
)

type Record struct {
	ID         string    `json:"id"`
	PeerID     string    `json:"peer_id,omitempty"`
	State      string    `json:"state,omitempty"`
	PID        int       `json:"pid,omitempty"`
	Cols       uint16    `json:"cols,omitempty"`
	Rows       uint16    `json:"rows,omitempty"`
	CreatedAt  string    `json:"created_at,omitempty"`
	Addr       string    `json:"addr,omitempty"`
	CertFP     string    `json:"cert_fp,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	Candidates []string  `json:"candidates,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type File struct {
	Sessions []Record `json:"sessions"`
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
		return nil, err
	}
	if f.Sessions == nil {
		f.Sessions = []Record{}
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{}
	}
	if f.Sessions == nil {
		f.Sessions = []Record{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

func (f *File) Get(id string) (Record, bool) {
	id = strings.TrimSpace(id)
	for _, r := range f.Sessions {
		if r.ID == id {
			return r, true
		}
	}
	return Record{}, false
}

func (f *File) Upsert(rec Record) {
	if rec.ID == "" {
		return
	}
	rec.UpdatedAt = time.Now().UTC()
	for i, cur := range f.Sessions {
		if cur.ID == rec.ID {
			if rec.PeerID == "" {
				rec.PeerID = cur.PeerID
			}
			if rec.Addr == "" {
				rec.Addr = cur.Addr
				rec.CertFP = cur.CertFP
				rec.Transport = cur.Transport
				rec.Candidates = cur.Candidates
			}
			if rec.CreatedAt == "" {
				rec.CreatedAt = cur.CreatedAt
			}
			f.Sessions[i] = rec
			return
		}
	}
	if rec.CreatedAt == "" {
		rec.CreatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
	}
	f.Sessions = append(f.Sessions, rec)
}

func CreatedDisplay(r Record) string {
	if r.CreatedAt != "" {
		return r.CreatedAt
	}
	if !r.UpdatedAt.IsZero() {
		return r.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return ""
}

func (f *File) BackfillCreated() bool {
	changed := false
	for i := range f.Sessions {
		if f.Sessions[i].CreatedAt != "" {
			continue
		}
		if f.Sessions[i].UpdatedAt.IsZero() {
			continue
		}
		f.Sessions[i].CreatedAt = f.Sessions[i].UpdatedAt.UTC().Format(time.RFC3339)
		changed = true
	}
	return changed
}

func (f *File) MergeAliases(adoc *alias.File) {
	if adoc == nil {
		return
	}
	aliasNames := map[string]struct{}{}
	for _, e := range adoc.Aliases {
		if n := strings.TrimSpace(e.Name); n != "" {
			aliasNames[n] = struct{}{}
		}
	}
	for _, e := range adoc.Aliases {
		if e.SessionID == "" {
			continue
		}
		// Corrupt entries sometimes stored the alias name as session_id;
		// never promote those into the session catalog as fake ids.
		if _, bad := aliasNames[e.SessionID]; bad {
			continue
		}
		if rec, ok := f.Get(e.SessionID); ok {
			if rec.PeerID == "" {
				rec.PeerID = e.PeerID
				f.Upsert(rec)
			}
			continue
		}
		f.Upsert(Record{
			ID:     e.SessionID,
			PeerID: e.PeerID,
			State:  "DETACHED",
		})
	}
}

// PruneAliasNamedIDs drops catalog rows whose id equals an alias name.
// Those rows are leftovers from a bad alias write that used the alias as a
// session id (real session ids are opaque tokens, not human nicknames).
func (f *File) PruneAliasNamedIDs(adoc *alias.File) bool {
	if f == nil || adoc == nil || len(adoc.Aliases) == 0 {
		return false
	}
	names := map[string]struct{}{}
	for _, e := range adoc.Aliases {
		if n := strings.TrimSpace(e.Name); n != "" {
			names[n] = struct{}{}
		}
	}
	out := f.Sessions[:0]
	changed := false
	for _, r := range f.Sessions {
		if _, isAliasName := names[r.ID]; isAliasName {
			changed = true
			continue
		}
		out = append(out, r)
	}
	f.Sessions = out
	return changed
}

func (f *File) MergeRecent(r *recent.File) {
	if r == nil || r.SessionID == "" {
		return
	}
	if _, ok := f.Get(r.SessionID); ok {
		return
	}
	f.Upsert(Record{
		ID:     r.SessionID,
		PeerID: r.PeerID,
		State:  "DETACHED",
	})
}

func listKey(r Record) string {
	if r.CreatedAt != "" {
		return r.CreatedAt
	}
	if !r.UpdatedAt.IsZero() {
		return r.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return ""
}

func (f *File) List() []Record {
	out := append([]Record(nil), f.Sessions...)
	sort.Slice(out, func(i, j int) bool {
		closedI := strings.EqualFold(out[i].State, "CLOSED")
		closedJ := strings.EqualFold(out[j].State, "CLOSED")
		if closedI != closedJ {
			return !closedI
		}
		return listKey(out[i]) > listKey(out[j]) // newest CreatedAt first
	})
	return out
}

func Remember(path string, rec Record) error {
	f, err := Load(path)
	if err != nil {
		return err
	}
	f.Upsert(rec)
	return Save(path, f)
}

func FromInfo(info protocol.SessionInfo, peerID, addr, certFP, transport string, candidates []string) Record {
	return Record{
		ID:         info.ID,
		PeerID:     peerID,
		State:      info.State,
		PID:        info.PID,
		Cols:       info.Cols,
		Rows:       info.Rows,
		CreatedAt:  info.CreatedAt,
		Addr:       addr,
		CertFP:     certFP,
		Transport:  transport,
		Candidates: append([]string(nil), candidates...),
	}
}
