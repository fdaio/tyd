package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// connectStatus is a single-line TTY progress bar on stderr.
// It is cleared when the session is live so the PTY owns the screen.
type connectStatus struct {
	w     io.Writer
	tty   bool
	on    bool
	pause time.Duration
}

func newConnectStatus(w *os.File) *connectStatus {
	if w == nil {
		return &connectStatus{}
	}
	return &connectStatus{w: w, tty: term.IsTerminal(int(w.Fd())), pause: 150 * time.Millisecond}
}

func (s *connectStatus) Step(n, total int, msg string) {
	if s == nil || !s.tty || s.w == nil {
		return
	}
	if total < 1 {
		total = 1
	}
	if n < 0 {
		n = 0
	}
	if n > total {
		n = total
	}
	bar := strings.Repeat("=", n) + strings.Repeat("-", total-n)
	s.on = true
	fmt.Fprintf(s.w, "\r[%s] %s\033[K", bar, msg)
}

func (s *connectStatus) Clear() {
	if s == nil || !s.tty || !s.on || s.w == nil {
		return
	}
	fmt.Fprint(s.w, "\r\033[K")
	s.on = false
}

// Leave flashes a final status, clears it, then writes a newline so zsh
// does not print PROMPT_EOL_MARK ("%") for a partial line.
func (s *connectStatus) Leave(msg string) {
	if s == nil || !s.tty || s.w == nil {
		return
	}
	s.Step(4, 4, msg)
	if s.pause > 0 {
		time.Sleep(s.pause)
	}
	s.Clear()
	fmt.Fprint(s.w, "\n")
}
