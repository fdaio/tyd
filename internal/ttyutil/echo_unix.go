//go:build unix

package ttyutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ReadEchoState reads the line-discipline state of a pty. The master and slave of
// a pty share one line discipline, so reading the master reports the slave's
// state — which is the shell's view, not ours.
//
// fd is a pty master, not a slave: the session's own side of the terminal is what
// a keystroke is written to, and the master's read describes it.
func ReadEchoState(fd int) (EchoState, error) {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return EchoState{}, fmt.Errorf("%w: %v", ErrNotATerminal, err)
	}
	return EchoState{
		Echo:   t.Lflag&unix.ECHO != 0,
		Icanon: t.Lflag&unix.ICANON != 0,
	}, nil
}
