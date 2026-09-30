// Package mcp serves tyd sessions to a model over MCP on stdio.
//
// The tools live here and the transport lives in cmd/tyd, so a tool can be
// exercised against a fake backend instead of a real daemon. Nothing in this
// package talks to a daemon directly: it drives a Backend.
package mcp

import (
	"context"
	"time"
)

// Session identifies one session on one target. A tool call names a session by
// alias or id, and a peer only when the process was started with more than one
// target.
type Session struct {
	ID    string
	Alias string
	// Peer is the target label, empty for the local daemon. It is part of the
	// identity because the same alias on two targets is two sessions.
	Peer string
}

// Key is the per-session lock and cursor key. Two sessions that share it are
// read and written one at a time.
func (s Session) Key() string { return s.Peer + "/" + s.ID }

// OpenRequest is what session_open was asked for.
type OpenRequest struct {
	// Name is the requested alias. Empty means the server picks agent-N.
	Name string
	// Shell is validated on the target daemon, not here.
	Shell string
	// Peer is empty for the default target.
	Peer string
}

// Opened is a session the backend just created, recorded locally so a human
// can take it over.
type Opened struct {
	Session Session
	// HumanAttach is the command that attaches to the session from a terminal.
	HumanAttach string
	// State is the state the target reported at creation. A remote target in
	// pre-approval mode answers PENDING until the operator approves.
	State string
}

// Listed is one row of session_list: what the local catalog knows, plus what a
// probe read found.
type Listed struct {
	Session Session
	// Recorded is the state the catalog holds. A probe updates it.
	Recorded string
	// State is running, exited, pending, unknown or closed. It is empty when no
	// probe ran.
	State string
	// ProbeError is why the probe did not answer, when it did not.
	ProbeError string
	// OpenedByUs marks a session this process created.
	OpenedByUs bool
	// Created is the catalog creation time, for display only.
	Created string
}

// Wait is the optional wake-up rule for a read. The zero value waits for the
// deadline alone.
type Wait struct {
	Match    string
	IdleMS   uint32
	MaxBytes uint32
	WaitMS   uint32
}

// Any reports whether a wake-up rule was given. A rule with no wait would
// return at once, which is the opposite of what the caller asked for.
func (w Wait) Any() bool { return w.Match != "" || w.IdleMS > 0 || w.MaxBytes > 0 }

// ReadRequest is one read. Cursor and Epoch are zero for a session this process
// has not touched.
type ReadRequest struct {
	Session Session
	Cursor  uint64
	Epoch   uint64
	Wait    time.Duration
	Cond    Wait
	// Progress, when set, is called while the read is parked so the caller can
	// keep the client's request timer alive.
	Progress func()
}

// Page is one read reply, in raw stream bytes. The cursor arithmetic belongs to
// the backend; this package only reports positions.
type Page struct {
	Data        []byte
	CursorNext  uint64
	Dropped     uint64
	Epoch       uint64
	CursorAhead bool
	Exited      bool
	Reason      string
}

// Sent is what a send reports. Written counts the bytes that reached the PTY,
// which is not always all of them.
type Sent struct {
	Written int
	// Cursor is the output position from before the write, so the read that
	// follows sees only what these keys produced.
	Cursor uint64
	Epoch  uint64
	// State is the session state the target reported, when it reported one.
	State string
}

// Backend is everything the tools need from tyd. The real implementation lives
// in cmd/tyd; tests use a fake.
type Backend interface {
	// Open creates a session without attaching, then records it locally.
	Open(ctx context.Context, req OpenRequest) (Opened, error)
	// Resolve maps an alias or a session id to a session on an allowed target.
	Resolve(ctx context.Context, ref, peer string) (Session, error)
	// List returns the sessions the local catalog knows. It reads local files
	// only and never opens a connection.
	List(ctx context.Context) ([]Listed, error)
	// Send injects bytes into a session nobody is attached to.
	Send(ctx context.Context, s Session, data []byte) (Sent, error)
	// Read pulls one page of output.
	Read(ctx context.Context, req ReadRequest) (Page, error)
	// Close ends a session.
	Close(ctx context.Context, s Session) error
}
