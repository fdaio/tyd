//go:build linux

package procs

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Process ancestry and peer credentials on Linux, both from the kernel: the
// parent chain out of /proc, and the connecting process of a unix socket from
// SO_PEERCRED. Neither needs privileges beyond reading our own /proc entries.

func parentPID(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// The second field is the executable name in parentheses and may itself
	// contain spaces and parentheses, so the fields after it are located from
	// the last ')'. What follows is state, then PPID.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0
	}
	fields := strings.Fields(string(b[i+2:]))
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// processLooksLikeSession reports whether a process is a tyd session shell.
//
// /proc/<pid>/environ is readable only for our own processes, so for an ancestor
// we fall back to what the kernel exposes to everyone: the command line, which
// tyd sets to a recognisable name. A shell started by tyd runs under a title
// carrying the session id.
func processLooksLikeSession(pid int) bool {
	cmd := readCmdline(pid)
	if cmd == "" {
		return false
	}
	return strings.Contains(cmd, sessionTitleMarker)
}

const sessionTitleMarker = "tyd-session:"

func readCmdline(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// peerPID returns the pid on the other end of a unix socket.
func peerPID(fd uintptr) (int, bool) {
	cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || cred == nil {
		return 0, false
	}
	return int(cred.Pid), true
}
