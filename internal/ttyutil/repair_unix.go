//go:build unix

package ttyutil

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Repair fixes a tty left in raw mode (e.g. after kill during attach).
// MakeRaw clears OPOST/ONLCR, so bare \n then staircases on session list etc.
func Repair() {
	seen := map[int]struct{}{}
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if f == nil {
			continue
		}
		fd := int(f.Fd())
		if !term.IsTerminal(fd) {
			continue
		}
		if _, ok := seen[fd]; ok {
			continue
		}
		seen[fd] = struct{}{}
		_ = restoreCooked(fd)
	}
}

func restoreCooked(fd int) error {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return err
	}
	t.Oflag |= unix.OPOST | unix.ONLCR
	t.Lflag |= unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN
	return unix.IoctlSetTermios(fd, ioctlWriteTermios, t)
}
