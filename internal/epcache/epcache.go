// Package epcache caches Control Panel peer data-plane endpoints on disk
// so session commands can skip a CP round-trip when the entry is still fresh.
package epcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tyd/internal/controlpanel"
)

type Entry struct {
	Addr       string    `json:"addr"`
	CertFP     string    `json:"cert_fp"`
	Transport  string    `json:"transport,omitempty"`
	Candidates []string  `json:"candidates,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type File struct {
	Peers map[string]Entry `json:"peers"`
}

var mu sync.Mutex

func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Peers: map[string]Entry{}}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Peers == nil {
		f.Peers = map[string]Entry{}
	}
	return &f, nil
}

func Save(path string, f *File) error {
	if f == nil {
		f = &File{Peers: map[string]Entry{}}
	}
	if f.Peers == nil {
		f.Peers = map[string]Entry{}
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

// Get returns a non-expired cached endpoint for peerID.
func Get(path, peerID string) (*controlpanel.EndpointResponse, bool) {
	mu.Lock()
	defer mu.Unlock()
	f, err := Load(path)
	if err != nil || peerID == "" {
		return nil, false
	}
	e, ok := f.Peers[peerID]
	if !ok || !time.Now().Before(e.ExpiresAt) {
		return nil, false
	}
	return &controlpanel.EndpointResponse{
		Addr:       e.Addr,
		CertFP:     e.CertFP,
		Transport:  e.Transport,
		Candidates: append([]string(nil), e.Candidates...),
		ExpiresAt:  e.ExpiresAt,
	}, true
}

func Put(path, peerID string, ep *controlpanel.EndpointResponse) error {
	if peerID == "" || ep == nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	f, err := Load(path)
	if err != nil {
		return err
	}
	f.Peers[peerID] = Entry{
		Addr:       ep.Addr,
		CertFP:     ep.CertFP,
		Transport:  ep.Transport,
		Candidates: append([]string(nil), ep.Candidates...),
		ExpiresAt:  ep.ExpiresAt,
	}
	return Save(path, f)
}

func Invalidate(path, peerID string) error {
	if peerID == "" {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	f, err := Load(path)
	if err != nil {
		return err
	}
	if _, ok := f.Peers[peerID]; !ok {
		return nil
	}
	delete(f.Peers, peerID)
	return Save(path, f)
}
