//go:build !unix

package ttyutil

// ReadEchoState has no line discipline to read off unix.
func ReadEchoState(fd int) (EchoState, error) {
	return EchoState{}, ErrNotATerminal
}
