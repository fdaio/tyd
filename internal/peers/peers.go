// Package peers persists Control Panel registration and paired peer public keys.
package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type File struct {
	Platform     string        `json:"platform,omitempty"`
	Registration *Registration `json:"registration,omitempty"`
	Peers        []Peer        `json:"peers"`
}

type Registration struct {
	ID           string    `json:"id"`
	PublicKey    string    `json:"public_key"`
	ApprovalMode string    `json:"approval_mode"`
	URL          string    `json:"url,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

type Peer struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	Nickname  string    `json:"nickname,omitempty"`
	Direction string    `json:"direction,omitempty"`
	PairedAt  time.Time `json:"paired_at"`
}

func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Peers: nil}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("peers file: %w", err)
	}
	if f.Peers == nil {
		f.Peers = []Peer{}
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{}
	}
	if f.Peers == nil {
		f.Peers = []Peer{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (f *File) UpsertPeer(p Peer) {
	for i, cur := range f.Peers {
		if cur.ID == p.ID || cur.PublicKey == p.PublicKey {
			f.Peers[i] = p
			return
		}
	}
	f.Peers = append(f.Peers, p)
}

func (f *File) MergePeers(list []Peer) {
	for _, p := range list {
		f.UpsertPeer(p)
	}
}

// ReplaceFromRemote sets the peer list from CP, keeping local nicknames when CP has none.
func (f *File) ReplaceFromRemote(list []Peer) {
	nicks := make(map[string]string, len(f.Peers))
	for _, p := range f.Peers {
		if p.Nickname != "" {
			nicks[p.ID] = p.Nickname
		}
	}
	out := make([]Peer, 0, len(list))
	for _, p := range list {
		if p.Nickname == "" {
			p.Nickname = nicks[p.ID]
		}
		out = append(out, p)
	}
	f.Peers = out
}

func (f *File) RemovePeer(idOrNick string) (*Peer, error) {
	p, err := f.Find(idOrNick)
	if err != nil {
		return nil, err
	}
	filtered := f.Peers[:0]
	for _, cur := range f.Peers {
		if cur.ID == p.ID {
			continue
		}
		filtered = append(filtered, cur)
	}
	f.Peers = filtered
	return p, nil
}

// Find resolves a peer by CP id or nickname.
func (f *File) Find(idOrNick string) (*Peer, error) {
	idOrNick = strings.TrimSpace(idOrNick)
	if idOrNick == "" {
		return nil, fmt.Errorf("empty peer")
	}
	var byNick *Peer
	for i := range f.Peers {
		p := &f.Peers[i]
		if p.ID == idOrNick {
			out := *p
			return &out, nil
		}
		if p.Nickname != "" && p.Nickname == idOrNick {
			byNick = p
		}
	}
	if byNick != nil {
		out := *byNick
		return &out, nil
	}
	return nil, fmt.Errorf("unknown peer %q", idOrNick)
}

// Outbound returns peers this side may dial (direction outbound).
func (f *File) Outbound() []Peer {
	var out []Peer
	for _, p := range f.Peers {
		if p.Direction == "outbound" || p.Direction == "" {
			out = append(out, p)
		}
	}
	return out
}

// HasRegistration reports whether this daemon registered with CP.
func (f *File) HasRegistration() bool {
	return f != nil && f.Registration != nil && f.Registration.ID != ""
}
