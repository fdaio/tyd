package mcp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"tyd/internal/live"
)

// oldPeerTag is the first release whose daemon answers a send. An older target
// rejects the frame by name instead, and the raw message ("unknown type
// \"send\"") tells a model nothing about what to do next.
const oldPeerTag = "2026.09.29-3d2132f"

// toolError is a failure a model can act on. It is reported as a tool result
// with isError set, never as a JSON-RPC error, because the call itself was
// well formed: the session was busy, the target is too old, the shell exited.
type toolError struct {
	msg string
}

func (e toolError) Error() string { return e.msg }

func toolErrf(format string, args ...any) error {
	return toolError{msg: fmt.Sprintf(format, args...)}
}

// ToolError reports whether err is a tool-level failure. The caller uses it to
// decide between a result with isError and a JSON-RPC error.
func ToolError(err error) (string, bool) {
	var te toolError
	if errors.As(err, &te) {
		return te.msg, true
	}
	return "", false
}

// mapError turns a target-side failure into something a model can act on. The
// wording is the whole point: a model retries a send it should have split, or
// types a password it was told not to type, unless the message says what to do.
func mapError(err error, s Session) error {
	if err == nil {
		return nil
	}
	if _, ok := ToolError(err); ok {
		return err
	}
	msg := err.Error()
	low := strings.ToLower(msg)

	switch {
	case strings.Contains(low, "session in use"):
		return toolErrf("someone is attached to %s, so a send is refused. "+
			"Reading still works. Retry later, or ask them to detach with Ctrl-\\ . "+
			"(the target said: %s)", s.Label(), msg)

	case strings.Contains(low, "session busy"):
		return toolErrf("a send to %s is already in progress. Wait for it to finish, then retry. "+
			"(%s)", s.Label(), msg)

	case strings.Contains(low, "send timed out"), strings.Contains(low, "preempted"):
		// The written count arrives on the error path, so the message cannot be
		// built here; the caller adds it.
		return toolErrf("the send to %s stopped part way: %s. "+
			"Read the session before sending again, and do not resend bytes that were already written.", s.Label(), msg)

	case strings.Contains(low, "pending approval"):
		return toolErrf("%s is waiting for approval on the target. "+
			"Ask the operator to run `tyd session approve %s` on that machine. "+
			"Nothing was sent. The request on the target gives up after %d s, so approve before then "+
			"or open a new session.", s.ID, s.ID, int(approvalDeadline/time.Second))

	case strings.Contains(low, "permission denied"):
		return toolErrf("this peer is not allowed to do that on %s (%s). "+
			"The owner has to re-pair it with the missing capability; retrying will not help.", s.Label(), msg)

	case strings.Contains(low, "already closed"), strings.Contains(low, "is closed"):
		return toolErrf("%s is closed. Call session_open to start a new one; "+
			"a closed session does not come back. (%s)", s.Label(), msg)

	case strings.Contains(low, "shell exited"), strings.Contains(low, "no running agent"),
		strings.Contains(low, "not supported on in-process"):
		return toolErrf("the shell behind %s is gone, so a send cannot reach it: %s. "+
			"Call session_close, then session_open for a fresh shell.", s.Label(), msg)

	case strings.Contains(low, "unknown type \"send\""), strings.Contains(low, "unknown type \"read\""),
		strings.Contains(low, "expected attach, watch, read, or close"):
		return toolErrf("the tyd on the target does not know send or read, so it is older than %s. "+
			"Ask the operator to upgrade tyd on that machine. (%s)", oldPeerTag, msg)

	case strings.Contains(low, "pattern too long"), strings.Contains(low, "bad pattern"):
		return toolErrf("the target rejected the wait pattern (%s). "+
			"A pattern is at most %d bytes of RE2, for example \"password:\" or \"^\\\\S+@\\\\S+$\".",
			msg, live.MaxMatchPattern)

	case strings.Contains(low, "too many reads waiting"):
		return toolErrf("the target already has the maximum number of reads waiting on %s. "+
			"Retry once one of them returns. (%s)", s.Label(), msg)

	case strings.Contains(low, "socket path too long"), strings.Contains(low, "name too long"):
		return toolErrf("a path on the target is too long for a unix socket: %s. "+
			"The target has to shorten its state directory or run with a shorter HOME.", msg)
	}

	// A connection failure is reported, never retried: an automatic retry would
	// repeat a send whose outcome is unknown.
	return toolErrf("%s (target: %s). This is a connection or protocol failure; "+
		"do not retry a send blindly, because the bytes may already have landed.", msg, s.Label())
}

// Label is how a session is named in a message: the alias when it has one.
func (s Session) Label() string {
	if s.Alias != "" {
		return s.Alias
	}
	return s.ID
}

// withWritten adds the byte count a partial send reported, so the model knows
// how much landed without counting bytes itself.
func withWritten(err error, written, total int) error {
	if err == nil {
		return nil
	}
	msg, ok := ToolError(err)
	if !ok {
		return err
	}
	return toolError{msg: fmt.Sprintf("%s\nwritten %d of %d bytes.", msg, written, total)}
}
