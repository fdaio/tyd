package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// connectStatus prints SSH-style verbose connect logs on stderr when enabled.
// Default is silent. Leave always ends with a newline so zsh does not print '%'.
type connectStatus struct {
	w       io.Writer
	verbose bool
}

func newConnectStatus(w *os.File, verbose bool) *connectStatus {
	if w == nil {
		return &connectStatus{}
	}
	return &connectStatus{w: w, verbose: verbose}
}

func (s *connectStatus) enabled() bool {
	return s != nil && s.verbose && s.w != nil
}

// writeln ends with CRLF so lines stay left-aligned even when the tty is in
// raw mode (after MakeRaw, or if a previous kill left the terminal raw).
func (s *connectStatus) writeln(line string) {
	fmt.Fprintf(s.w, "%s\r\n", line)
}

// Notice always writes a user-facing line (not gated on --verbose).
func (s *connectStatus) Notice(msg string) {
	if s == nil || s.w == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	s.writeln(msg)
}

// Log writes one SSH-style debug line when verbose.
func (s *connectStatus) Log(msg string) {
	if !s.enabled() {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	s.writeln("debug1: " + msg)
}

// Clear is a no-op for line-oriented verbose logs (kept for call sites).
func (s *connectStatus) Clear() {}

// Leave logs an optional final message (when verbose) and always writes a newline.
func (s *connectStatus) Leave(msg string) {
	if s == nil || s.w == nil {
		return
	}
	if s.verbose {
		msg = strings.TrimSpace(msg)
		if msg != "" {
			s.writeln("debug1: " + msg)
			return
		}
	}
	fmt.Fprint(s.w, "\r\n")
}

func dialDebugMsg(kind, addr string) string {
	kind = strings.TrimSpace(kind)
	addr = strings.TrimSpace(addr)
	if kind == "" {
		kind = "tcp"
	}
	if kind == "unix" || strings.HasPrefix(addr, "/") {
		return fmt.Sprintf("Connecting to unix %s.", addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Sprintf("Connecting to %s %s.", kind, addr)
	}
	return fmt.Sprintf("Connecting to %s port %s.", host, port)
}
