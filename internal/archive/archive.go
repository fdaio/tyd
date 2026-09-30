// Package archive holds what tyd remembers about its own peers and sessions
// that the files rebuilt from the Control Panel cannot carry.
//
// peers.json is rebuilt from whatever the Control Panel returns on every sync,
// and `doctor --fix` replaces it outright, so a mark written there is lost by
// the next round. The clock a peer is judged on would go with it, and a peer in
// daily use would then be archived on the strength of its pairing date. Both
// therefore live here, in a file only the client writes.
//
// An archived peer keeps its entry in peers.json and its record in paired.json,
// and stays dialable. Archiving hides a peer from the default views; it grants
// and withdraws nothing. `tyd revoke` is the act that withdraws access.
package archive

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tyd/internal/safefile"
)

// MarshalJSON leaves out a clock that was never set. time.Time is a struct, so
// omitempty cannot do it, and a state file carrying year-1 timestamps reads as a
// measurement that was taken.
func (p Peer) MarshalJSON() ([]byte, error) {
	out := make(map[string]time.Time, 2)
	if !p.LastUsed.IsZero() {
		out["last_used"] = p.LastUsed
	}
	if !p.ArchivedAt.IsZero() {
		out["archived_at"] = p.ArchivedAt
	}
	return json.Marshal(out)
}

// File is the whole archive: one entry per peer and per session, keyed by id.
// A missing key means the thing is not archived.
type File struct {
	Peers    map[string]Peer    `json:"peers,omitempty"`
	Sessions map[string]Session `json:"sessions,omitempty"`
}

// Peer is what the archive remembers about one peer.
//
// LastUsed is the client's own record of when it last dialled the peer, kept
// here because peers.json cannot hold it. It is the clock a peer is archived
// on; a peer with no entry falls back to its pairing time.
type Peer struct {
	LastUsed   time.Time `json:"last_used,omitempty"`
	ArchivedAt time.Time `json:"archived_at,omitempty"`
}

// Session is what the archive remembers about one session.
//
// The use clock is not here: sessions.json is written only by this client and
// is never rebuilt, so a session record carries its own. Only the mark, which
// has to be readable without the record, lives in this file.
type Session struct {
	ArchivedAt time.Time `json:"archived_at,omitempty"`
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
		return nil, fmt.Errorf("archive file: %w", err)
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

// Update applies fn to the file and saves the result, holding an exclusive lock
// across the whole read-modify-write.
//
// The lock cannot live on the archive file itself: Save replaces the inode, so
// a lock taken on the old one would not be the lock a second process waits for.
// It also cannot be taken after the read, because the read is the half that
// races. The lock file is therefore a file of its own, and it stays behind on
// purpose: deleting it would let a process lock an unlinked name while another
// holds the only inode still in use.
//
// fn reports whether it changed anything. When it did not, nothing is written,
// so a prune that finds nothing new leaves the file, and its mtime, alone.
func Update(path string, fn func(*File) bool) error {
	release, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer release()
	f, err := Load(path)
	if err != nil {
		return err
	}
	if !fn(f) {
		return nil
	}
	return Save(path, f)
}

// PeerArchived reports whether the peer is hidden from the default views.
func (f *File) PeerArchived(id string) bool {
	if f == nil {
		return false
	}
	p, ok := f.Peers[id]
	return ok && !p.ArchivedAt.IsZero()
}

// SessionArchived reports whether the session is hidden from the default views.
func (f *File) SessionArchived(id string) bool {
	if f == nil {
		return false
	}
	s, ok := f.Sessions[id]
	return ok && !s.ArchivedAt.IsZero()
}

// TouchPeer stamps the dial clock and puts an archived peer back, reporting
// whether it changed the file. A peer that is dialled again is in use, and
// hiding it would hide the peer the operator just reached for.
func (f *File) TouchPeer(id string, now time.Time) bool {
	if id == "" {
		return false
	}
	cur := f.Peers[id]
	if cur.LastUsed.Equal(now) && cur.ArchivedAt.IsZero() {
		return false
	}
	if f.Peers == nil {
		f.Peers = make(map[string]Peer)
	}
	f.Peers[id] = Peer{LastUsed: now}
	return true
}

// TouchSession puts an archived session back, reporting whether it changed the
// file. Its clock is the session record's own, so there is nothing to stamp.
func (f *File) TouchSession(id string) bool {
	if id == "" {
		return false
	}
	cur, ok := f.Sessions[id]
	if !ok || cur.ArchivedAt.IsZero() {
		return false
	}
	delete(f.Sessions, id)
	return true
}

// ArchivePeer hides a peer from the default views, reporting whether it changed
// the file. An already archived peer is left alone, which is what keeps a
// repeated prune from rewriting the file for nothing.
func (f *File) ArchivePeer(id string, now time.Time) bool {
	if id == "" || f.PeerArchived(id) {
		return false
	}
	cur := f.Peers[id]
	if f.Peers == nil {
		f.Peers = make(map[string]Peer)
	}
	cur.ArchivedAt = now
	f.Peers[id] = cur
	return true
}

// ArchiveSession hides a session from the default views, reporting whether it
// changed the file.
func (f *File) ArchiveSession(id string, now time.Time) bool {
	if id == "" || f.SessionArchived(id) {
		return false
	}
	if f.Sessions == nil {
		f.Sessions = make(map[string]Session)
	}
	f.Sessions[id] = Session{ArchivedAt: now}
	return true
}

// RestorePeer puts a peer back in the default views and reports whether it was
// archived. The dial clock moves to now with it: the operator asked for this
// peer back, which is as good a reason to keep it as dialling it again would
// be, and without that a restored peer is archived by the very next list.
func (f *File) RestorePeer(id string, now time.Time) bool {
	if f == nil {
		return false
	}
	cur, ok := f.Peers[id]
	if !ok || cur.ArchivedAt.IsZero() {
		return false
	}
	cur.ArchivedAt = time.Time{}
	cur.LastUsed = now
	f.Peers[id] = cur
	return true
}

// RestoreSession puts a session back in the default views and reports whether
// it was archived.
func (f *File) RestoreSession(id string) bool {
	if f == nil || !f.SessionArchived(id) {
		return false
	}
	return f.ForgetSession(id)
}

// ForgetSession drops everything the archive holds about a session and reports
// whether there was anything. A session that no longer exists leaves a mark
// behind, and an id is the only key a mark has.
func (f *File) ForgetSession(id string) bool {
	if f == nil {
		return false
	}
	if _, ok := f.Sessions[id]; !ok {
		return false
	}
	delete(f.Sessions, id)
	return true
}

// ForgetPeer drops everything the archive holds about a peer and reports whether
// there was anything.
func (f *File) ForgetPeer(id string) bool {
	if f == nil {
		return false
	}
	if _, ok := f.Peers[id]; !ok {
		return false
	}
	delete(f.Peers, id)
	return true
}

// PeerLastUsed is when the client last dialled the peer, or the zero time when
// it has never dialled it. The caller decides what a peer with no clock means;
// the pairing time is a fallback that lives in peers.json, not here.
func (f *File) PeerLastUsed(id string) time.Time {
	if f == nil {
		return time.Time{}
	}
	return f.Peers[id].LastUsed
}
