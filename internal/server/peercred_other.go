//go:build !linux

package server

// macOS does have peer credentials, but LOCAL_PEERCRED reports the peer's user
// rather than its pid, and getting a pid would need proc_pidinfo, which x/sys
// does not expose. So on macOS and elsewhere the daemon-side check is absent
// and only the CLI-side guard applies; docs/security.md says so.
func peerPID(uintptr) (int, bool) { return 0, false }
