// Package peerstate keeps the daemon's Control Panel registration and peer
// list in memory and treats peers.json as a cache of it.
//
// The daemon used to re-read peers.json on every maintenance tick, so one
// unreadable file (a full disk truncating it, say) took down CP sync, endpoint
// publishing, and peer trust even though the process already held all of it.
// Here memory is authoritative: writes are best effort, a failed write is
// remembered and retried, and a file that no longer parses is ignored rather
// than believed.
package peerstate

import (
	"sync"

	"tyd/internal/peers"
)

type State struct {
	mu    sync.Mutex
	path  string
	doc   *peers.File
	dirty bool // memory holds changes that are not on disk
}

// Load reads path into memory. A missing file yields empty state; an
// unparsable one is an error, so the caller can decide how to recover.
func Load(path string) (*State, error) {
	doc, err := peers.Load(path)
	if err != nil {
		return nil, err
	}
	return &State{path: path, doc: doc}, nil
}

// New wraps an in-memory document. A nil doc starts empty.
func New(path string, doc *peers.File) *State {
	if doc == nil {
		doc = &peers.File{Peers: []peers.Peer{}}
	}
	return &State{path: path, doc: doc}
}

func (s *State) Path() string { return s.path }

func clone(in *peers.File) *peers.File {
	out := &peers.File{Platform: in.Platform}
	if in.Registration != nil {
		reg := *in.Registration
		out.Registration = &reg
	}
	out.Peers = append([]peers.Peer(nil), in.Peers...)
	return out
}

// Snapshot returns a copy callers may read and mutate freely.
func (s *State) Snapshot() *peers.File {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.doc)
}

func (s *State) HasRegistration() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.HasRegistration()
}

// Registration returns a copy of the registration, if there is one.
func (s *State) Registration() (peers.Registration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.doc.HasRegistration() {
		return peers.Registration{}, false
	}
	return *s.doc.Registration, true
}

// Platform returns the recorded CP base URL, or fallback when unset.
func (s *State) Platform(fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doc.Platform != "" {
		return s.doc.Platform
	}
	return fallback
}

func (s *State) ApprovalMode(fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doc.Registration != nil && s.doc.Registration.ApprovalMode != "" {
		return s.doc.Registration.ApprovalMode
	}
	return fallback
}

// Update applies fn to the in-memory document and then tries to persist it.
// The memory change always sticks; the returned error only reports the write.
func (s *State) Update(fn func(*peers.File)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.doc)
	s.dirty = true
	return s.persistLocked()
}

// Flush retries a write that failed earlier. It is a no-op when in sync.
func (s *State) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.persistLocked()
}

func (s *State) persistLocked() error {
	if err := peers.Save(s.path, s.doc); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// Dirty reports whether memory is ahead of disk.
func (s *State) Dirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirty
}

// ReloadIfSane adopts the on-disk file when it parses and memory has nothing
// unsaved, so edits made by short-lived CLI commands are picked up. A file
// that no longer parses is left alone and memory keeps serving.
func (s *State) ReloadIfSane() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return false
	}
	doc, err := peers.Load(s.path)
	if err != nil {
		return false
	}
	s.doc = doc
	return true
}
