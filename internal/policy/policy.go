// Package policy holds the local role for each paired peer.
//
// The file lives beside peers.json and is written only by this machine. The
// Control Panel can withhold a pairing; it cannot grant a role.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tyd/internal/auth"
	"tyd/internal/safefile"
)

type Role string

const (
	// RoleList can use list-level commands and nothing else.
	RoleList Role = "list"
	// RoleViewer can watch and read any session. It cannot attach
	// interactively, write, resize, signal, or close.
	RoleViewer Role = "viewer"
	// RoleOperator can create sessions and owns the ones it creates.
	RoleOperator Role = "operator"
	// RoleAdmin has both the viewer and operator capabilities.
	RoleAdmin Role = "admin"

	// DefaultRole is what a peer gets when the file does not name it. It is
	// deliberately the narrowest role.
	DefaultRole = RoleList
)

// Entry is one peer's policy.
type Entry struct {
	Role Role `json:"role"`
}

// File is the on-disk policy.
type File struct {
	DefaultRole Role             `json:"default_role"`
	Peers       map[string]Entry `json:"peers,omitempty"`
}

// PathFor is where the policy lives for a given peers.json.
func PathFor(peersPath string) string {
	return filepath.Join(filepath.Dir(peersPath), "policy.json")
}

// Load reads the policy. A missing file is os.ErrNotExist, so a caller can
// distinguish "no policy yet" from "a policy that does not parse".
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if f.DefaultRole == "" {
		f.DefaultRole = DefaultRole
	}
	if f.Peers == nil {
		f.Peers = make(map[string]Entry)
	}
	return &f, nil
}

// Ensure loads the policy, or creates one that keeps every existing peer
// working: those peers become operators and the default for future peers is
// list. A new install with no peers therefore starts at list.
func Ensure(path string, peerIDs []string) (*File, error) {
	f, err := Load(path)
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f = &File{DefaultRole: RoleList, Peers: make(map[string]Entry)}
	for _, id := range peerIDs {
		if id = strings.TrimSpace(id); id != "" {
			f.Peers[id] = Entry{Role: RoleOperator}
		}
	}
	if err := f.Save(path); err != nil {
		return nil, err
	}
	return f, nil
}

// Save writes the policy atomically with mode 0600.
func (f *File) Save(path string) error {
	if f.DefaultRole == "" {
		f.DefaultRole = DefaultRole
	}
	if f.Peers == nil {
		f.Peers = make(map[string]Entry)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safefile.WriteFile(path, append(b, '\n'), 0o600)
}

// RoleFor returns the peer's role, or the file default.
func (f *File) RoleFor(peerID string) Role {
	if f == nil {
		return DefaultRole
	}
	if e, ok := f.Peers[strings.TrimSpace(peerID)]; ok && e.Role != "" {
		return e.Role
	}
	if f.DefaultRole == "" {
		return DefaultRole
	}
	return f.DefaultRole
}

// Set records a role for one peer.
func (f *File) Set(peerID string, role Role) error {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return fmt.Errorf("peer id is required")
	}
	if err := Validate(role); err != nil {
		return err
	}
	if f.Peers == nil {
		f.Peers = make(map[string]Entry)
	}
	f.Peers[peerID] = Entry{Role: role}
	return nil
}

// Validate parses a role name from a command line.
func Validate(role Role) error {
	switch Role(strings.ToLower(strings.TrimSpace(string(role)))) {
	case RoleList, RoleViewer, RoleOperator, RoleAdmin:
		return nil
	default:
		return fmt.Errorf("role %q: want list, viewer, operator, or admin", role)
	}
}

// Caps translates a role into the capabilities the trust store holds.
func Caps(role Role) ([]auth.Cap, error) {
	switch Role(strings.ToLower(strings.TrimSpace(string(role)))) {
	case RoleList:
		return []auth.Cap{auth.CapList}, nil
	case RoleViewer:
		return []auth.Cap{auth.CapList, auth.CapWatchAny, auth.CapReadAny}, nil
	case RoleOperator:
		return []auth.Cap{auth.CapList, auth.CapCreate}, nil
	case RoleAdmin:
		return []auth.Cap{auth.CapList, auth.CapCreate, auth.CapWatchAny, auth.CapReadAny}, nil
	default:
		return nil, fmt.Errorf("role %q: want list, viewer, operator, or admin", role)
	}
}
