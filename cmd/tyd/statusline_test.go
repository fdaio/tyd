package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"tyd/internal/client"
)

func TestConnectStatusNoticeAlways(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, verbose: false}
	s.Notice("watching (read-only)")
	s.Log("should stay silent")
	if buf.String() != "watching (read-only)\r\n" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestConnectStatusVerboseSSHStyle(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, verbose: true}
	s.Log("Connecting to 10.0.0.1 port 22.")
	s.Log("Connection established.")
	got := buf.String()
	if !strings.Contains(got, "debug1: Connecting to 10.0.0.1 port 22.\r\n") {
		t.Fatalf("connect: %q", got)
	}
	if !strings.Contains(got, "debug1: Connection established.\r\n") {
		t.Fatalf("established: %q", got)
	}
	s.Leave("Detaching.")
	if !strings.HasSuffix(buf.String(), "debug1: Detaching.\r\n") {
		t.Fatalf("leave: %q", buf.String())
	}
}

func TestDialDebugMsg(t *testing.T) {
	got := dialDebugMsg("tls", "100.101.29.23:34759")
	if got != "Connecting to 100.101.29.23 port 34759." {
		t.Fatalf("%q", got)
	}
	got = dialDebugMsg("unix", "/tmp/tyd.sock")
	if got != "Connecting to unix /tmp/tyd.sock." {
		t.Fatalf("%q", got)
	}
}

// A status line is for a person watching a terminal. A pipe, a log, and a script
// must see only the result.
func TestTerminalLineSilentOnPipe(t *testing.T) {
	var buf bytes.Buffer
	if terminalLine(&buf, "connecting…") {
		t.Fatal("terminalLine wrote to a pipe")
	}
	if buf.Len() != 0 {
		t.Fatalf("pipe got %q", buf.String())
	}
}

func TestTerminalLineWritesOnTerminal(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptmx.Close()
	defer tty.Close()

	if !terminalLine(tty, "connecting to abc over tls…") {
		t.Fatal("terminalLine did not write to a terminal")
	}
	buf := make([]byte, 256)
	n, err := ptmx.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "connecting to abc over tls…") {
		t.Fatalf("terminal got %q", got)
	}
}

func TestConnectStatusProgressSilentOnPipe(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf}
	if s.Progress("waiting for approval…") {
		t.Fatal("Progress wrote to a pipe")
	}
	s.connecting("0123456789abcdef", "quic")
	if buf.Len() != 0 {
		t.Fatalf("pipe got %q", buf.String())
	}
}

func TestConnectingSkipsALocalSession(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf}
	// No peer means a local dial, which returns at once: no line.
	s.connecting("", "unix")
	if buf.Len() != 0 {
		t.Fatalf("local session got %q", buf.String())
	}
}

func TestShortTransport(t *testing.T) {
	if got := shortTransport(""); got != "unix" {
		t.Errorf("shortTransport(%q) = %q, want unix", "", got)
	}
	if got := shortTransport("tls"); got != "tls" {
		t.Errorf("shortTransport(%q) = %q, want tls", "tls", got)
	}
}

// captureTerminal runs fn with a terminal as its writer and returns what the
// terminal received.
func captureTerminal(t *testing.T, fn func(*os.File)) string {
	t.Helper()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	fn(tty)
	// A read on a pty with nothing written blocks, and macOS ignores read
	// deadlines on ptys, so read in a goroutine and stop waiting on our own.
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _ := ptmx.Read(buf)
		done <- buf[:n]
	}()
	select {
	case b := <-done:
		return string(b)
	case <-time.After(500 * time.Millisecond):
		return ""
	}
}

// The dial path is spelled out on a terminal: direct first, then the relay.
func TestBindDialEventsOnTerminal(t *testing.T) {
	var ep client.Endpoint
	got := captureTerminal(t, func(tty *os.File) {
		st := newConnectStatus(tty, false)
		bindDialEvents(&ep, st, "tls")
		ep.OnDial("203.0.113.7:443")
		ep.OnFallback()
		ep.OnDial("relay wss://relay.example")
		ep.OnConnected("relay")
	})
	for _, want := range []string{
		"direct: 203.0.113.7:443",
		"direct failed; trying the relay…",
		"relay: wss://relay.example",
		"connected via the relay.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal did not show %q: %q", want, got)
		}
	}
	if strings.Index(got, "direct: ") > strings.Index(got, "connected via the relay.") {
		t.Fatalf("paths are out of order: %q", got)
	}
}

func TestBindDialEventsDirectOnTerminal(t *testing.T) {
	var ep client.Endpoint
	got := captureTerminal(t, func(tty *os.File) {
		st := newConnectStatus(tty, false)
		bindDialEvents(&ep, st, "quic")
		ep.OnDial("203.0.113.7:443")
		ep.OnConnected("direct")
	})
	for _, want := range []string{"direct: 203.0.113.7:443", "connected directly."} {
		if !strings.Contains(got, want) {
			t.Fatalf("terminal did not show %q: %q", want, got)
		}
	}
}

// --verbose already reports each step as a debug line; it must not get a second
// set of friendly lines.
func TestBindDialEventsSilentWhenVerbose(t *testing.T) {
	var ep client.Endpoint
	got := captureTerminal(t, func(tty *os.File) {
		st := newConnectStatus(tty, true)
		bindDialEvents(&ep, st, "tls")
		ep.OnDial("203.0.113.7:443")
		ep.OnFallback()
		ep.OnDial("relay wss://relay.example")
		ep.OnConnected("relay")
	})
	if !strings.Contains(got, "debug1:") {
		t.Fatalf("verbose should keep its debug lines: %q", got)
	}
	for _, unwanted := range []string{"direct: ", "relay: ", "connected via the relay.", "connected directly."} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("verbose gained %q: %q", unwanted, got)
		}
	}
}

func TestBindDialEventsSilentOnPipe(t *testing.T) {
	var buf bytes.Buffer
	st := newConnectStatus(nil, false)
	st.w = &buf
	var ep client.Endpoint
	bindDialEvents(&ep, st, "tls")
	ep.OnDial("203.0.113.7:443")
	ep.OnFallback()
	ep.OnDial("relay wss://relay.example")
	ep.OnConnected("relay")
	if buf.Len() != 0 {
		t.Fatalf("pipe got %q", buf.String())
	}
}

// A unix socket is local: there is no direct-versus-relay choice to report.
func TestBindDialEventsSilentForLocalSocket(t *testing.T) {
	var ep client.Endpoint
	got := captureTerminal(t, func(tty *os.File) {
		st := newConnectStatus(tty, false)
		bindDialEvents(&ep, st, "unix")
		ep.OnDial("/tmp/tyd.sock")
		ep.OnConnected("direct")
	})
	if strings.TrimSpace(got) != "" {
		t.Fatalf("local socket got %q", got)
	}
}
