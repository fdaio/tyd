// Package endpointcache stores peer endpoints that passed signature
// verification against the local pairing record.
//
// The Control Panel is a courier for endpoint records, not their author: each
// record is signed by the peer and checked against the key learned at pairing.
// Keeping a verified copy locally lets a dial start without asking the Control
// Panel, and a Control Panel outage no longer stops a dial to an address this
// client has already accepted.
//
// The cache is not a trust source. A record is verified again on every read
// against paired.json, so a tampered cache entry, an entry for another peer, or
// an entry for a peer this machine never paired is ignored.
package endpointcache

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"tyd/internal/auth"
	"tyd/internal/safefile"
)

// fileVersion lets a later layout be told apart from this one.
const fileVersion = 1

type File struct {
	Version int     `json:"version"`
	Peers   []Entry `json:"peers"`
}

// Entry is one verified record. Sig is the peer's signature over Record.
type Entry struct {
	PeerID string              `json:"peer_id"`
	Record auth.EndpointRecord `json:"record"`
	Sig    string              `json:"sig"`
}

// Load reads the cache. A missing file is an empty cache; an unreadable one is
// an error so the caller can treat it as absent without trusting its contents.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Version: fileVersion}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("endpoint cache: %w", err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("endpoint cache: unsupported version %d", f.Version)
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{}
	}
	f.Version = fileVersion
	f.sort()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

// Lookup returns the entry stored for peerID.
func (f *File) Lookup(peerID string) (Entry, bool) {
	for _, e := range f.Peers {
		if e.PeerID == peerID {
			return e, true
		}
	}
	return Entry{}, false
}

// Verified returns the entry's record when the signature checks out against
// pub and the record names the same peer.
func (e Entry) Verified(pub ed25519.PublicKey) (auth.EndpointRecord, bool) {
	if e.PeerID == "" || e.Record.DaemonID != e.PeerID {
		return auth.EndpointRecord{}, false
	}
	sig, err := auth.DecodeBytes(e.Sig)
	if err != nil {
		return auth.EndpointRecord{}, false
	}
	if err := e.Record.Verify(pub, sig); err != nil {
		return auth.EndpointRecord{}, false
	}
	return e.Record, true
}

// Store verifies e against pub and then persists it. A cache that no longer
// parses is replaced rather than trusted or reported as a dial failure.
func Store(path string, e Entry, pub ed25519.PublicKey) error {
	if _, ok := e.Verified(pub); !ok {
		return fmt.Errorf("endpoint cache: refusing to store an unverified record for %s", e.PeerID)
	}
	f, err := Load(path)
	if err != nil {
		f = &File{}
	}
	f.Upsert(e)
	return Save(path, f)
}

// Upsert adds or replaces the entry for the same peer.
func (f *File) Upsert(e Entry) {
	for i := range f.Peers {
		if f.Peers[i].PeerID == e.PeerID {
			f.Peers[i] = e
			f.sort()
			return
		}
	}
	f.Peers = append(f.Peers, e)
	f.sort()
}

func (f *File) sort() {
	sort.Slice(f.Peers, func(i, j int) bool { return f.Peers[i].PeerID < f.Peers[j].PeerID })
}
