package main

import (
	"fmt"
	"os"
	"strings"
)

// applyAttachShortcut rewrites `tyd <session>.<peer>` into
// `tyd --peer <peer> session attach <session>`.
// The left side is a session alias or id; the right side is a peer nickname or id.
// The token must contain exactly one dot, and both sides must be non-empty.
func applyAttachShortcut(opts *options) error {
	if opts == nil || !strings.Contains(opts.cmd, ".") {
		return nil
	}
	sessionRef, peerRef, ok := splitSessionPeer(opts.cmd)
	if !ok {
		return fmt.Errorf("usage: tyd <session>.<peer> (session alias or id, peer alias or id; exactly one dot)")
	}
	if len(opts.rest) != 0 {
		return fmt.Errorf("usage: tyd <session>.<peer>")
	}
	if opts.peer != "" && opts.peer != peerRef {
		return fmt.Errorf("--peer %q does not match %q in %s", opts.peer, peerRef, opts.cmd)
	}
	opts.peer = peerRef
	opts.cmd = "session"
	opts.rest = []string{"attach", sessionRef}
	return nil
}

func splitSessionPeer(token string) (sessionRef, peerRef string, ok bool) {
	sessionRef, peerRef, found := strings.Cut(token, ".")
	if !found || sessionRef == "" || peerRef == "" || strings.Contains(peerRef, ".") {
		return "", "", false
	}
	return sessionRef, peerRef, true
}

// warnDotName says, at the moment a name is stored, that the dot in it costs
// the user the `tyd <session>.<peer>` shortcut. Such a name is still a legal
// alias — only the shortcut cannot parse it: two dots make the token a usage
// error, and one dot would split the name in the wrong place. Nothing here
// rejects the name; the long form stays the way to reach it.
func warnDotName(kind, name, longForm string) {
	if !strings.Contains(name, ".") {
		return
	}
	fmt.Fprintf(os.Stderr,
		"warning: %s %q contains a '.', so `tyd <session>.<peer>` cannot use it; use %s\n",
		kind, name, longForm)
}
