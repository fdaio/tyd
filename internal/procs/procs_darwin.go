//go:build darwin

package procs

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Process ancestry on macOS comes from the kernel's process table. Peer
// credentials exist too -- LOCAL_PEERCRED reports the peer's user, not its pid,
// and getting a pid would need proc_pidinfo, which x/sys does not expose -- so
// the daemon-side check is Linux only. The environment marker and the CLI-side
// walk still apply here; docs/security.md says what that leaves out.

func parentPID(pid int) int {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return 0
	}
	return int(kp.Eproc.Ppid)
}

func processLooksLikeSession(pid int) bool {
	// A process of ours can be asked directly; anything else needs privileges
	// we do not have, so the walk stops there and the environment marker (which
	// children inherit) is what actually catches a session shell.
	if pid != os.Getpid() {
		return false
	}
	return os.Getenv(EnvSessionID) != ""
}

func readCmdline(pid int) string {
	// Best effort, for the same reason: only our own process is readable.
	if pid != os.Getpid() {
		return ""
	}
	arg := ""
	if len(os.Args) > 0 {
		arg = os.Args[0]
	}
	return strings.TrimSpace(arg + " " + strconv.Itoa(pid))
}

func peerPID(fd uintptr) (int, bool) { return 0, false }
