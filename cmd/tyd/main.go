package main

import (
	"fmt"
	"os"
	"path/filepath"

	"tyd/internal/live"
	"tyd/internal/ttyutil"
)

const (
	ansiCyan   = "\033[36m"
	ansiReset  = "\033[0m"
	helpColPad = 22
)

func main() {
	ttyutil.Repair()
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(2)
	}
	if opts.cmd == "" || opts.cmd == "help" || opts.cmd == "-h" || opts.cmd == "--help" {
		usage()
		return
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if err := applyAttachShortcut(&opts); err != nil {
		return err
	}
	// Resolved once, here, for every command — including the daemon ones.
	//
	// It used to be resolved only inside __live-agent, which is the child process. The
	// daemon and `tyd mcp` read opts.fileRoot directly, so on the path anyone actually
	// runs, `--file-root /` was not refused, $HOME was not refused without the switch,
	// and the path was never made absolute or checked. The helper was correct and fully
	// unit-tested, which is exactly how that stayed invisible: nothing tested the wiring.
	if opts.fileRoot != "" {
		root, err := resolveFileRoot(opts.fileRoot, opts.fileRootAllowHome)
		if err != nil {
			return err
		}
		opts.fileRoot = root
	}
	switch opts.cmd {
	case "__live-agent":
		return runLiveAgent(opts)
	case "keygen":
		return runKeygen(opts)
	case "up":
		if err := refuseIfInSession("up"); err != nil {
			return err
		}
		return runUp(opts)
	case "serve":
		fmt.Fprintln(os.Stderr, "note: 'tyd serve' is deprecated; prefer 'tyd up'")
		if err := refuseIfInSession("serve"); err != nil {
			return err
		}
		return runUp(opts)
	case "register":
		if err := refuseIfInSession("register"); err != nil {
			return err
		}
		return runRegister(opts)
	case "invite":
		if err := refuseIfInSession("invite"); err != nil {
			return err
		}
		return runInvite(opts)
	case "accept":
		if err := refuseIfInSession("accept"); err != nil {
			return err
		}
		return runAccept(opts)
	case "revoke":
		if err := refuseIfInSession("revoke"); err != nil {
			return err
		}
		return runRevoke(opts)
	case "status":
		return runStatus(opts)
	case "alias":
		fmt.Fprintln(os.Stderr, "note: prefer 'tyd session alias'")
		return runAlias(opts)
	case "mcp":
		return runMCP(opts)
	case "session":
		return runSession(opts)
	case "peer":
		return runPeer(opts)
	case "audit":
		return runAuditVerify(opts)
	case "approval":
		if err := refuseIfInSession("approval"); err != nil {
			return err
		}
		return runApproval(opts)
	case "doctor":
		return runDoctor(opts)
	case "create", "list", "attach", "close", "watch":
		return fmt.Errorf("unknown command %q; use: tyd session %s", opts.cmd, opts.cmd)
	default:
		return unknownCommandErr("command", opts.cmd, rootCommands(), "")
	}
}

func runLiveAgent(opts options) error {
	if opts.dir == "" {
		return fmt.Errorf("__live-agent requires --dir")
	}
	// Already resolved by run, on the same path every other command takes. Resolving it
	// again here would print the $HOME warning twice for a daemon that spawns agents.
	return live.Run(opts.dir, live.Config{FileRoot: opts.fileRoot})
}

// resolveFileRoot applies the two refusals the design fixes, and returns an absolute
// path.
//
// `/` is refused with no switch. Any use that genuinely needs the whole filesystem
// wants a narrower root, and a flag that permits `/` is a flag that turns off the
// only guarantee this feature makes — so the way to get it is to not use this
// feature, which is a decision someone can see in a process list.
//
// `$HOME` is refused unless the operator asked for it, because it is a real default
// for a shell-based tool and an unreasonable root for a file API: it is where the
// keys, the tokens and the shell startup files all live. It is available, and
// saying so out loud is the price.
func resolveFileRoot(given string, allowHome bool) (string, error) {
	abs, err := filepath.Abs(given)
	if err != nil {
		return "", fmt.Errorf("--file-root %s: %w", given, err)
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) {
		return "", fmt.Errorf("--file-root %s: the filesystem root is refused and cannot be allowed; "+
			"give a directory the session may work in", given)
	}
	if home, err := os.UserHomeDir(); err == nil && abs == filepath.Clean(home) {
		if !allowHome {
			return "", fmt.Errorf("--file-root %s: $HOME is refused unless --file-root-allow-home is given; "+
				"a home directory holds keys and tokens as well as work", given)
		}
		// Loud, once, on stderr: this is the root where .ssh and .aws are.
		fmt.Fprintf(os.Stderr, "tyd: file operations are rooted at $HOME (%s); "+
			"this includes ssh keys, cloud credentials and shell startup files\n", abs)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("--file-root %s: %w", given, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--file-root %s: not a directory", given)
	}
	return abs, nil
}
