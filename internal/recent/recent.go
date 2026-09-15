// Package recent tracks the last peer used for session commands.
package recent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type File struct {
	PeerID    string    `json:"peer_id"`
	SessionID string    `json:"session_id,omitempty"`
	At        time.Time `json:"at"`
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func Remember(path, peerID, sessionID string) error {
	if peerID == "" {
		return nil
	}
	return Save(path, &File{
		PeerID:    peerID,
		SessionID: sessionID,
		At:        time.Now().UTC(),
	})
}
