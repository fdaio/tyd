// Package procs answers one question about the local machine: is this process,
// or the process on the other end of a socket, running inside a tyd session?
//
// It exists because tyd's approval and control commands are reachable from
// inside a session. The daemon, the session's shell, the identity key and the
// audit log all belong to the same user, and the unix socket that carries
// approve, reject and approval-mode changes is reachable by anything running as
// that user. So an agent inside a session can turn off approval, approve its own
// pending request, edit the log that records it, and read the key that makes it
// this daemon.
//
// Nothing here is a security boundary, and docs/security.md says so: a process
// can leave the session's process tree with setsid and a double fork, and the
// environment variable is trivially unset. What this does is make the obvious
// move -- run tyd approve from the shell you were just given -- fail, and say
// why. The real answer to "I do not trust what runs in my session" is to run
// the session somewhere else.
package procs

import (
	"errors"
	"os"
)

// maxAncestryDepth bounds the parent walk. A cycle in /proc would otherwise hang
// the CLI; 64 levels is far past any real process tree.
const maxAncestryDepth = 64

// ErrUnsupported is returned where the platform cannot answer the question.
var ErrUnsupported = errors.New("not supported on this platform")

// InSession reports whether this process is a descendant of a tyd session
// shell. A shell started by tyd carries TYD_SESSION in its environment, and its
// children inherit it; the parent walk catches anything that cleared it.
func InSession() bool {
	if os.Getenv(EnvSessionID) != "" {
		return true
	}
	in, err := DescendantOfSession(os.Getpid())
	return err == nil && in
}

// SessionMarker is the environment variable tyd puts in a session's shell.
const EnvSessionID = "TYD_SESSION"

// EnvPeerID is the peer id of the session, alongside the session id.
const EnvPeerID = "TYD_PEER"

// DescendantOfSession walks up from pid and reports whether any ancestor is a
// process this package can recognise as belonging to a session.
func DescendantOfSession(pid int) (bool, error) {
	seen := 0
	for cur := pid; cur > 1 && seen < maxAncestryDepth; seen++ {
		ppid := parentPID(cur)
		if ppid <= 0 {
			return false, nil
		}
		if isSessionProcess(ppid) {
			return true, nil
		}
		cur = ppid
	}
	return false, nil
}

// isSessionProcess reports whether pid is a tyd session shell. tyd names its
// session shells distinguishably, and a shell also inherits the marker.
func isSessionProcess(pid int) bool {
	if pid == os.Getpid() {
		return os.Getenv(EnvSessionID) != ""
	}
	return processLooksLikeSession(pid)
}

// AncestorPIDs returns pid's parent chain, nearest first, for diagnostics.
func AncestorPIDs(pid int) []int {
	var out []int
	seen := 0
	for cur := pid; cur > 1 && seen < maxAncestryDepth; seen++ {
		ppid := parentPID(cur)
		if ppid <= 0 {
			return out
		}
		out = append(out, ppid)
		cur = ppid
	}
	return out
}
