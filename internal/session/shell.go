package session

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// shellsFile lists the login shells a system considers valid. It is a var so
// a test can point it at a fixture instead of whatever the host happens to
// have, which would decide whether these tests pass.
var shellsFile = "/etc/shells"

// validateShell checks a shell the caller asked for by name.
//
// This runs on the daemon, not the client: the client may be on another
// host, where /etc/shells says nothing about this one.
//
// It is a typo guard, not a security control. A caller who can create a
// session can already run the default shell and therefore run anything, so
// an unlisted shell is refused to catch "I meant this path", not to contain
// anyone. The default shell is exempt for the same reason: refusing to start
// sessions because the daemon's own shell is unlisted would be a regression.
func validateShell(shell string) error {
	if shell == "" {
		return nil
	}
	f, err := os.Open(shellsFile)
	if err != nil {
		// Without the file there is nothing to check against, and the
		// requester can already run this shell as the default.
		return nil
	}
	defer f.Close()
	want := shell
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == want {
			return nil
		}
	}
	return fmt.Errorf("shell %q is not listed in %s on this host; "+
		"add it there, or pick one of the shells it lists", want, shellsFile)
}
