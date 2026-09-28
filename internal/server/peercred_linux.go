//go:build linux

package server

import "syscall"

// peerPID returns the pid on the other end of a unix socket, from the kernel's
// own record of the connection. This is the check the environment marker cannot
// be: a process that clears TYD_SESSION still has a pid the kernel knows.
func peerPID(fd uintptr) (int, bool) {
	cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || cred == nil {
		return 0, false
	}
	return int(cred.Pid), true
}
