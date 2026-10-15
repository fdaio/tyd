package session

// Deterministic agent-operation test framework.
//
// Philosophy (the mission under test):
//
//	tyd exists so an agent can drive a shell deterministically: after
//	`cd a`, a later `ls` runs in `a` — no focus loss, no guessing, like a
//	human. The shell remains the substrate; tyd adds a contract on top of
//	it that removes speculation from the agent's operation loop.
//
// The cardinal rule of this suite: the test driver must behave like an
// agent. It may ONLY use tyd primitives (Send/Read with cursors, wait
// conditions, unique markers) for control-flow decisions. If test code
// ever asks "does this output look like a shell prompt?", the test is
// invalid — because prompt-guessing is exactly what is under test.
//
// What is allowed:
//   - waiting for a unique marker the driver itself generated
//     (unambiguous: the driver knows the token, it is not guessing)
//   - cursor arithmetic (Send returns the cursor; Read resumes from it)
//   - declared wait conditions (Match / IdleMS / MaxBytes)
//
// What is forbidden in driver control flow:
//   - prompt detection ("$ ", "# ", ">>>") to decide completion
//   - sleep-then-hope polling without a declared condition
//   - parsing exit codes out of free text (use the marker protocol)

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tyd/internal/live"
)

var detMarkerSeq atomic.Uint64

// AgentDriver drives a session the way a disciplined agent should:
// every operation is attributed by cursor, completion is declared
// (unique marker), never guessed.
type AgentDriver struct {
	t *testing.T
	s *Session
}

func NewAgentDriver(t *testing.T, s *Session) *AgentDriver {
	t.Helper()
	return &AgentDriver{t: t, s: s}
}

// freshMarker returns a token no command output could plausibly contain.
// The token is also regex-safe, but callers must still pass it through
// regexp.QuoteMeta: Match is compiled as a regexp, and the token format
// is an implementation detail that must not become a latent dependency.
func freshMarker() string {
	n := detMarkerSeq.Add(1)
	return fmt.Sprintf("__TYD_DET_%d_%d__", time.Now().UnixNano(), n)
}

// extractMarker scans for the driver's own marker protocol line:
// "<marker>:<digits>". The PTY echoes the input line, which contains the
// marker followed by a literal "$?" — that echo must NOT be mistaken for
// the completion signal. Only a numeric suffix counts.
//
// Returns the output body (everything before the marker line) and the
// exit code. ok is false when no complete marker line is present yet.
func extractMarker(out, marker string) (body, code string, ok bool) {
	// The real marker line comes after the input echo, so scan from the
	// end: the last occurrence is the completion signal, if complete.
	idx := strings.LastIndex(out, marker)
	if idx < 0 {
		return "", "", false
	}
	rest := out[idx+len(marker):]
	if !strings.HasPrefix(rest, ":") {
		return "", "", false
	}
	rest = rest[1:]
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		// Suffix is not numeric yet — this is the input echo
		// ("echo MARKER:$?"), not the completion line. Keep waiting.
		return "", "", false
	}
	return out[:idx], rest[:i], true
}

// sendAndWait types cmd plus a marker line into the session and reads
// until the marker protocol line appears. It returns the command's
// output body (attributed by the cursor Send returned) and its exit
// code. Completion is declared, never guessed.
func (d *AgentDriver) sendAndWait(cmd string) (body, code string) {
	d.t.Helper()
	marker := freshMarker()
	reply, err := d.s.Send([]byte(cmd+"\necho "+marker+":$?\n"), false)
	if err != nil {
		d.t.Fatalf("send failed: %v", err)
	}
	// Start reading at the cursor Send reported: output before this point
	// belongs to earlier commands, not this one. QuoteMeta because Match
	// is compiled as a regexp.
	cursor, epoch := reply.Cursor, reply.Epoch
	match := regexp.QuoteMeta(marker)
	deadline := time.Now().Add(15 * time.Second)
	var acc []byte
	for time.Now().Before(deadline) {
		res, err := d.s.Read(cursor, epoch, 2*time.Second, live.ReadConditions{
			Match: match,
		})
		if err != nil {
			d.t.Fatalf("read failed: %v", err)
		}
		if res.CursorAhead {
			cursor, epoch = res.CursorNext, res.Epoch
			continue
		}
		cursor, epoch = res.CursorNext, res.Epoch
		acc = append(acc, res.Data...)
		if body, code, ok := extractMarker(string(acc), marker); ok {
			return body, code
		}
		if res.Exited {
			d.t.Fatalf("shell exited while waiting for marker %s, got %q", marker, acc)
		}
	}
	d.t.Fatalf("marker %s never completed, got %q", marker, acc)
	return "", ""
}

// Run sends cmd and returns everything the PTY emitted after the cursor
// Send returned — the input echo plus the command's output, up to the
// marker line. Attribution is by cursor (nothing from earlier commands
// leaks in); completion is declared via the marker line, never guessed.
func (d *AgentDriver) Run(cmd string) string {
	d.t.Helper()
	body, _ := d.sendAndWait(cmd)
	return body
}

// RunOK runs cmd and fails the test unless its exit code was 0.
func (d *AgentDriver) RunOK(cmd string) string {
	d.t.Helper()
	body, code := d.sendAndWait(cmd)
	if code != "0" {
		d.t.Fatalf("command %q exited with code %s, output: %q", cmd, code, body)
	}
	return body
}

// OutputContains fails unless out contains want.
func (d *AgentDriver) OutputContains(out, want string) {
	d.t.Helper()
	if !strings.Contains(out, want) {
		d.t.Fatalf("output missing %q, got %q", want, out)
	}
}
