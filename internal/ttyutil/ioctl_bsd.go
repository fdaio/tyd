//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package ttyutil

import "golang.org/x/sys/unix"

const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
