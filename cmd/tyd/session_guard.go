package main

import (
	"fmt"
	"os"
	"strings"

	"tyd/internal/procs"
)

// Control commands are the ones that change who may reach this machine or who
// may watch it: approving a pending session, rejecting one, changing the
// approval mode, minting or revoking an invite, replacing a pairing, starting a
// second daemon. They all act over the local unix socket, and that socket is
// reachable by anything running as this user -- including the shell of a session
// on this machine, which shares the daemon's home directory and therefore its
// identity key.
//
// So an agent inside a session could approve its own pending request, switch
// approval off, and rewrite the record of having done so. It can read ~/.tyd and
// kill the daemon whatever this does. This is not a boundary, and
// docs/security.md says so in those words. What it does is make the obvious move
// fail, and say why, instead of succeeding quietly.

// controlCommands are refused inside a session. Each entry is a full command
// path, so `tyd session list` stays available to an agent while
// `tyd session approve` does not: the first only reads, the second hands out
// access.
var controlCommands = map[string]bool{
	"session approve": true,
	"session reject":  true,
	"approval":        true,
	"revoke":          true,
	"invite":          true,
	"accept":          true,
	"register":        true,
	"up":              true,
	"serve":           true,
}

// refuseIfInSession is called at the top of a control command, before it does
// any work, so nothing is changed on the way to being refused.
func refuseIfInSession(command string) error {
	if !controlCommands[command] {
		return nil
	}
	if !procs.InSession() {
		return nil
	}
	// No override is offered, on purpose. The environment marker is already
	// something a session can clear, so an escape hatch would only make the
	// guard look optional in the one place a reader would take it seriously.
	session := procs.EnvSessionID + "=" + strings.TrimSpace(os.Getenv(procs.EnvSessionID))
	return fmt.Errorf("`tyd %s` is refused inside a tyd session (%s).\n"+
		"This shell runs as the same user as the daemon and shares its home, so it could "+
		"approve its own requests, turn approval off, or edit the log that records it.\n"+
		"Run it from a terminal outside the session, on the host itself.\n"+
		"This is a speed bump, not a boundary: see docs/security.md", command, session)
}
