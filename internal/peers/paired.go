package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"tyd/internal/auth"
	"tyd/internal/safefile"
)

// PairedFile is the local record of who this daemon will talk to.
//
// It exists because peers.json cannot hold that: peers.json is rebuilt from
// whatever the Control Panel returns (see ReplaceFromRemote), so a peer listed
// there is a peer the Control Panel asked for. This file is written only by
// pairing, verified by the daemon itself, and never handed to the Control
// Panel. Trust comes from here and nowhere else, which is what makes "the CP
// may withdraw trust but never grant it" true rather than aspirational.
type PairedFile struct {
	Peers []PairedPeer `json:"peers"`
}

// PairedPeer is one entry: the key, the metadata worth keeping, and the record
// that justifies trusting it.
type PairedPeer struct {
	ID        string             `json:"id"`
	PublicKey string             `json:"public_key"`
	Nickname  string             `json:"nickname,omitempty"`
	Direction string             `json:"direction,omitempty"`
	PairedAt  time.Time          `json:"paired_at"`
	Proof     *auth.PairingProof `json:"proof,omitempty"`
	// EndpointSeq is the highest publish sequence already accepted from this
	// peer. It is what makes a replayed -- but correctly signed -- endpoint
	// record detectable, across restarts.
	EndpointSeq uint64 `json:"endpoint_seq,omitempty"`
}

// Verified reports whether this entry may be trusted. A legacy entry is trusted
// through LegacyTrusted instead, which callers must opt into knowingly.
func (p PairedPeer) Verified() bool {
	return p.Proof.Verified()
}

// Legacy reports a peer paired before records existed. Such a peer keeps
// working so an upgrade does not cut anyone off, but its trust still rests on
// the Control Panel, and tyd says so in `peer show`.
func (p PairedPeer) Legacy() bool {
	return p.Proof == nil || p.Proof.Legacy
}

// Key decodes the entry's public key.
func (p PairedPeer) Key() ([]byte, error) {
	return auth.DecodePublic(p.PublicKey)
}

func LoadPaired(path string) (*PairedFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &PairedFile{}, nil
		}
		return nil, err
	}
	var f PairedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("paired file: %w", err)
	}
	return &f, nil
}

func SavePaired(path string, f *PairedFile) error {
	if f == nil {
		f = &PairedFile{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

// Find returns the entry for a peer id or nickname.
func (f *PairedFile) Find(idOrNick string) (PairedPeer, error) {
	for _, p := range f.Peers {
		if p.ID == idOrNick || (p.Nickname != "" && p.Nickname == idOrNick) {
			return p, nil
		}
	}
	return PairedPeer{}, fmt.Errorf("unknown peer %q", idOrNick)
}

// Upsert adds or replaces an entry, keeping the list ordered by id so the file
// does not churn between syncs.
func (f *PairedFile) Upsert(p PairedPeer) {
	for i := range f.Peers {
		if f.Peers[i].ID == p.ID {
			if p.Nickname == "" {
				p.Nickname = f.Peers[i].Nickname
			}
			f.Peers[i] = p
			f.sort()
			return
		}
	}
	f.Peers = append(f.Peers, p)
	f.sort()
}

func (f *PairedFile) Remove(idOrNick string) bool {
	for i := range f.Peers {
		if f.Peers[i].ID == idOrNick || (f.Peers[i].Nickname != "" && f.Peers[i].Nickname == idOrNick) {
			f.Peers = append(f.Peers[:i], f.Peers[i+1:]...)
			return true
		}
	}
	return false
}

func (f *PairedFile) sort() {
	sort.Slice(f.Peers, func(i, j int) bool { return f.Peers[i].ID < f.Peers[j].ID })
}

// SeedLegacy records peers that predate pairing records so an upgrade keeps
// them working. It runs once: the first daemon that finds no paired file adopts
// what it already had, and from then on the file is the only source of trust, so
// the Control Panel can no longer add to it.
//
// A peer that already has a real record keeps it.
func (f *PairedFile) SeedLegacy(from *File) int {
	if from == nil {
		return 0
	}
	known := make(map[string]bool, len(f.Peers))
	for _, p := range f.Peers {
		known[p.ID] = true
	}
	added := 0
	for _, p := range from.Peers {
		if known[p.ID] || p.PublicKey == "" {
			continue
		}
		f.Peers = append(f.Peers, PairedPeer{
			ID:        p.ID,
			PublicKey: p.PublicKey,
			Nickname:  p.Nickname,
			Direction: p.Direction,
			PairedAt:  p.PairedAt,
			Proof:     &auth.PairingProof{Legacy: true, PairedAt: p.PairedAt},
		})
		known[p.ID] = true
		added++
	}
	f.sort()
	return added
}

// KeepVerified prunes the file down to the peers still present upstream, but
// only ever removes: an entry is dropped when the Control Panel stops listing
// the peer, never added because it started listing one.
func (f *PairedFile) KeepVerified(keep map[string]bool) int {
	out := f.Peers[:0]
	dropped := 0
	for _, p := range f.Peers {
		if keep[p.ID] {
			out = append(out, p)
			continue
		}
		dropped++
	}
	f.Peers = out
	return dropped
}
