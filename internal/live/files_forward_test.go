package live

import (
	"net"
	"os"
	"strings"
	"testing"

	"tyd/internal/protocol"
)

// The tests here stand in for the agent so the two properties B2 has to prove can be
// tested where they are actually decided: that the frame crosses unaltered, and that a
// reply which lost its ID is caught rather than passed on. What the *agent* does with a
// frame is covered in files_test.go; what the *sender* does with a wrong reply is not
// observable from there.

// liveAgentDir makes a directory that Alive(dir) accepts and short enough to hold a
// unix socket in.
//
// Under /tmp rather than t.TempDir(), because a unix socket path is capped near 104
// bytes on macOS and t.TempDir() embeds the test's name — long enough to overflow on
// its own. The failure is `bind: invalid argument`, which says nothing about the cause.
func liveAgentDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tydfwd")
	if err != nil {
		t.Fatalf("short state dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := WritePID(AgentPIDPath(dir), os.Getpid()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// stubAgent serves the agent's socket with handle. It is the agent's side of the seam,
// reduced to what a test needs to control.
func stubAgent(t *testing.T, dir string, handle func(net.Conn)) {
	t.Helper()
	sock := SockPath(dir)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = os.Remove(sock)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
}

// Every field that changes what the agent does has to arrive. A field dropped in
// transit is not a missing feature: the agent acts on a default, and for `Root` or
// `Mode` that default is a *different operation*.
func TestEveryFieldReachesTheAgent(t *testing.T) {
	dir := liveAgentDir(t)
	got := make(chan protocol.Frame, 1)
	stubAgent(t, dir, func(conn net.Conn) {
		defer conn.Close()
		f, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		got <- f
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeFileResult, ID: f.ID})
	})

	req := protocol.Frame{
		Type: protocol.TypeFileWrite, ID: "req-42",
		SessionID:   "sess1",
		Path:        "docs/notes.md",
		Root:        "sub",
		Mode:        "replace",
		Offset:      7,
		MaxBytes:    4096,
		ExpectedSHA: strings.Repeat("a", 64),
		Data:        []byte("the content"),
	}
	if _, err := DialFile(dir, req); err != nil {
		t.Fatal(err)
	}
	arrived := <-got

	// Compared field by field on purpose: one struct comparison would also pass if both
	// sides were zero, which is the failure being looked for.
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"type", arrived.Type, req.Type},
		{"id", arrived.ID, req.ID},
		{"session_id", arrived.SessionID, req.SessionID},
		{"path", arrived.Path, req.Path},
		{"root", arrived.Root, req.Root},
		{"mode", arrived.Mode, req.Mode},
		{"offset", arrived.Offset, req.Offset},
		{"max_bytes", arrived.MaxBytes, req.MaxBytes},
		{"expected_sha256", arrived.ExpectedSHA, req.ExpectedSHA},
		{"data", string(arrived.Data), string(req.Data)},
	} {
		if c.got != c.want {
			t.Errorf("%s arrived as %v, want %v", c.name, c.got, c.want)
		}
	}
}

// A reply that lost its ID cannot be matched to its request. Passing it on would leave
// the caller to attribute it by timeout, which is how a wrong file gets blamed on a
// right one.
func TestAReplyThatLostItsIDIsRefused(t *testing.T) {
	dir := liveAgentDir(t)
	stubAgent(t, dir, func(conn net.Conn) {
		defer conn.Close()
		if _, err := protocol.ReadFrame(conn); err != nil {
			return
		}
		// The agent forgot to echo it — a plausible bug in a hand-written handler.
		_ = protocol.WriteFrame(conn, protocol.Frame{
			Type: protocol.TypeFileResult, SHA256: "deadbeef", Bytes: 10,
		})
	})

	_, err := DialFile(dir, protocol.Frame{Type: protocol.TypeFileRead, ID: "req-1", Path: "a.txt"})
	if err == nil {
		t.Fatal("a reply with no ID was accepted")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("the error does not say what was wrong: %v", err)
	}
}

// An agent that answers with the wrong type is refused rather than decoded as a
// result, because a mis-typed frame decoded as a file result is a read of nothing.
func TestAnUnexpectedReplyTypeIsRefused(t *testing.T) {
	dir := liveAgentDir(t)
	stubAgent(t, dir, func(conn net.Conn) {
		defer conn.Close()
		f, _ := protocol.ReadFrame(conn)
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeOK, ID: f.ID})
	})
	_, err := DialFile(dir, protocol.Frame{Type: protocol.TypeFileRead, ID: "r", Path: "a.txt"})
	if err == nil || !strings.Contains(err.Error(), "unexpected file reply") {
		t.Fatalf("want an unexpected-reply error, got %v", err)
	}
}

// The agent's refusal reaches the caller as text, because that text is what a model
// reads and what tells it the operation was refused rather than lost.
func TestAnAgentRefusalReachesTheCaller(t *testing.T) {
	dir := liveAgentDir(t)
	stubAgent(t, dir, func(conn net.Conn) {
		defer conn.Close()
		f, _ := protocol.ReadFrame(conn)
		_ = protocol.WriteFrame(conn, protocol.Frame{
			Type: protocol.TypeFileResult, ID: f.ID, Error: "blocked_path: .bashrc",
		})
	})
	_, err := DialFile(dir, protocol.Frame{Type: protocol.TypeFileWrite, ID: "r", Path: ".bashrc"})
	if err == nil || !strings.Contains(err.Error(), "blocked_path") {
		t.Fatalf("the agent's refusal did not reach the caller: %v", err)
	}
}

// No agent means no answer, and the reason says so rather than reporting a missing
// file — the difference between "the session is gone" and "that file is not there".
func TestNoAgentIsReportedAsSuch(t *testing.T) {
	dir := t.TempDir()
	if err := WritePID(AgentPIDPath(dir), 999999); err != nil {
		t.Fatal(err)
	}
	_, err := DialFile(dir, protocol.Frame{Type: protocol.TypeFileRead, Path: "a.txt"})
	if err == nil || !strings.Contains(err.Error(), "no running agent") {
		t.Fatalf("want a no-agent error, got %v", err)
	}
}
