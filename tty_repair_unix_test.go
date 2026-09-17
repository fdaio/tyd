//go:build unix

package main

import (
	"os"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestRestoreCookedEnablesONLCR(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	fd := int(tty.Fd())

	raw, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		t.Fatal(err)
	}
	raw.Oflag &^= unix.OPOST | unix.ONLCR
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, raw); err != nil {
		t.Fatal(err)
	}

	if err := restoreCooked(fd); err != nil {
		t.Fatal(err)
	}
	got, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		t.Fatal(err)
	}
	if got.Oflag&unix.OPOST == 0 || got.Oflag&unix.ONLCR == 0 {
		t.Fatalf("OPOST/ONLCR not restored: oflag=%#x", got.Oflag)
	}
	if got.Lflag&unix.ICANON == 0 {
		t.Fatalf("ICANON not restored: lflag=%#x", got.Lflag)
	}
}

// silence unused import if pty path changes
var _ = os.ErrClosed
