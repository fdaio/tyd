package main

import (
	"fmt"
	"os"

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
	switch opts.cmd {
	case "__live-agent":
		return runLiveAgent(opts)
	case "keygen":
		return runKeygen(opts)
	case "up":
		return runUp(opts)
	case "serve":
		fmt.Fprintln(os.Stderr, "note: 'tyd serve' is deprecated; prefer 'tyd up'")
		return runUp(opts)
	case "register":
		return runRegister(opts)
	case "invite":
		return runInvite(opts)
	case "accept":
		return runAccept(opts)
	case "revoke":
		return runRevoke(opts)
	case "status":
		return runStatus(opts)
	case "alias":
		fmt.Fprintln(os.Stderr, "note: prefer 'tyd session alias'")
		return runAlias(opts)
	case "session":
		return runSession(opts)
	case "peer":
		return runPeer(opts)
	case "approval":
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
	return live.Run(opts.dir)
}
