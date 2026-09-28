//go:build !linux && !darwin

package procs

// Every other platform answers "no": there is no process-tree check here, so a
// control command from inside a session is only caught by the environment
// marker, which that shell's children inherit. FreeBSD and the rest are built
// and released, so this file has to exist for them to compile at all.
// docs/security.md lists where the checks are available.

func parentPID(int) int { return 0 }

func processLooksLikeSession(int) bool { return false }

func peerPID(uintptr) (int, bool) { return 0, false }
