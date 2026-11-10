package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/creack/pty"
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
