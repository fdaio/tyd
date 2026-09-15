// Package peers persists Control Panel registration and paired peer public keys.
package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
