// Package audit records session control events for later review.
//
// Events carry metadata only. Terminal input, terminal output, and process
// environment must never reach a sink — the Event type has no field for them.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Kind string

const (
	KindCreate        Kind = "create"
	KindCreatePending Kind = "create_pending"
	KindApprove       Kind = "approve"
	KindReject        Kind = "reject"
	KindAttach        Kind = "attach"
	KindAttachPending Kind = "attach_pending"
	KindDetach        Kind = "detach"
	KindClose         Kind = "close"
	KindIdleClose     Kind = "idle_close"
	KindDenied        Kind = "denied"
)

type Event struct {
	Time       time.Time `json:"time"`
	Kind       Kind      `json:"event"`
	SessionID  string    `json:"session_id,omitempty"`
	Principal  string    `json:"principal,omitempty"`
	PeerID     string    `json:"peer_id,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	Approval   string    `json:"approval_mode,omitempty"`
	Capability string    `json:"capability,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  string    `json:"created_at,omitempty"`
	ExitCode   *int      `json:"exit_code,omitempty"`
}

type Sink interface {
	Log(Event)
}

// FuncSink adapts a function to Sink (tests, custom routing).
type FuncSink func(Event)

func (fn FuncSink) Log(e Event) { fn(e) }

type discard struct{}

func (discard) Log(Event) {}

// Discard drops every event.
func Discard() Sink { return discard{} }

// File appends JSON Lines to a file created 0600.
type File struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

func OpenFile(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &File{f: f, path: path}, nil
}

func (a *File) Path() string { return a.path }

func (a *File) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.f.Write(append(b, '\n'))
}

func (a *File) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}
