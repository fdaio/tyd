package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
	"tyd/internal/controlpanel"
	"tyd/internal/live"
	"tyd/internal/paths"
)

type options struct {
	socket             string
	listen             string
	dataListen         string
	advertise          string
	addr               string
	peer               string
	relay              string
	identity           string
	trust              string
	peers              string
	paired             string
	recent             string
	aliases            string
	sessions           string
	platform           string
	approval           string
	fix                bool
	auditLog           string
	sessionIdle        time.Duration
	outputLogMax       int64
	sessionSendTimeout time.Duration
	shell              string
	as                 string
	cert               string
	key                string
	noWait             bool
	detach             bool
	readOnly           bool
	closeOnExit        bool
	maxSessions        int
	allowPeer          []string
	verbose            bool
	force              bool
	cmd                string
	rest               []string
	live               string
	dir                string
}

func parseArgs(args []string) (options, error) {
	opts := options{
		socket:       paths.DefaultSocket(),
		listen:       paths.DefaultListen(),
		dataListen:   paths.DefaultDataListen(),
		advertise:    paths.DefaultAdvertise(),
		identity:     paths.DefaultIdentity(),
		trust:        paths.DefaultTrust(),
		peers:        paths.DefaultPeers(),
		recent:       paths.DefaultRecent(),
		aliases:      paths.DefaultAliases(),
		sessions:     paths.DefaultSessions(),
		live:         paths.DefaultLive(),
		platform:     paths.DefaultPlatform(),
		relay:        paths.DefaultRelay(),
		approval:     controlpanel.DefaultApproval,
		cert:         paths.DefaultServerCert(),
		key:          paths.DefaultServerKey(),
		outputLogMax: live.DefaultOutputLogMax,
	}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		// session read and session send own their flags. Once one of them is
		// in hand, hand the rest over untouched instead of rejecting the
		// flags it is going to parse itself. The session id may already be
		// here or may still be coming, so look for the subcommand rather than
		// assuming a position.
		if strings.HasPrefix(a, "-") {
			for k := 0; k+1 < len(positional); k++ {
				if positional[k] != "session" {
					continue
				}
				if positional[k+1] != "read" && positional[k+1] != "send" {
					continue
				}
				opts.cmd = "session"
				opts.rest = append(append([]string{}, positional[k+1:]...), args[i:]...)
				return opts, nil
			}
		}
		switch {
		case a == "-h" || a == "--help":
			opts.cmd = "help"
			return opts, nil
		case a == "--socket" || a == "-socket":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.socket = args[i]
		case strings.HasPrefix(a, "--socket="):
			opts.socket = strings.TrimPrefix(a, "--socket=")
		case a == "--listen":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires an address or 'off'", a)
			}
			i++
			opts.listen = args[i]
		case strings.HasPrefix(a, "--listen="):
			opts.listen = strings.TrimPrefix(a, "--listen=")
		case a == "--data-listen":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires auto|off|HOST:PORT", a)
			}
			i++
			opts.dataListen = args[i]
		case strings.HasPrefix(a, "--data-listen="):
			opts.dataListen = strings.TrimPrefix(a, "--data-listen=")
		case a == "--advertise":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a host", a)
			}
			i++
			opts.advertise = args[i]
		case strings.HasPrefix(a, "--advertise="):
			opts.advertise = strings.TrimPrefix(a, "--advertise=")
		case a == "--addr":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires host:port", a)
			}
			i++
			opts.addr = args[i]
		case strings.HasPrefix(a, "--addr="):
			opts.addr = strings.TrimPrefix(a, "--addr=")
		case a == "--peer":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires an id or nickname", a)
			}
			i++
			opts.peer = args[i]
		case strings.HasPrefix(a, "--peer="):
			opts.peer = strings.TrimPrefix(a, "--peer=")
		case a == "--relay":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a URL or 'off'", a)
			}
			i++
			opts.relay = args[i]
		case strings.HasPrefix(a, "--relay="):
			opts.relay = strings.TrimPrefix(a, "--relay=")
		case a == "--identity":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.identity = args[i]
		case strings.HasPrefix(a, "--identity="):
			opts.identity = strings.TrimPrefix(a, "--identity=")
		case a == "--trust":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.trust = args[i]
		case strings.HasPrefix(a, "--trust="):
			opts.trust = strings.TrimPrefix(a, "--trust=")
		case a == "--paired":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.paired = args[i]
		case strings.HasPrefix(a, "--paired="):
			opts.paired = strings.TrimPrefix(a, "--paired=")
		case a == "--peers":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.peers = args[i]
		case strings.HasPrefix(a, "--peers="):
			opts.peers = strings.TrimPrefix(a, "--peers=")
		case a == "--aliases":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.aliases = args[i]
		case strings.HasPrefix(a, "--aliases="):
			opts.aliases = strings.TrimPrefix(a, "--aliases=")
		case a == "--recent":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.recent = args[i]
		case strings.HasPrefix(a, "--recent="):
			opts.recent = strings.TrimPrefix(a, "--recent=")
		case a == "--platform":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a URL", a)
			}
			i++
			opts.platform = args[i]
		case strings.HasPrefix(a, "--platform="):
			opts.platform = strings.TrimPrefix(a, "--platform=")
		case a == "--approval":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires full|pre|post", a)
			}
			i++
			opts.approval = args[i]
		case strings.HasPrefix(a, "--approval="):
			opts.approval = strings.TrimPrefix(a, "--approval=")
		case a == "--audit-log":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.auditLog = args[i]
		case strings.HasPrefix(a, "--audit-log="):
			opts.auditLog = strings.TrimPrefix(a, "--audit-log=")
		case a == "--session-idle-timeout":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a duration (e.g. 8h) or 'off'", a)
			}
			i++
			d, err := parseIdleTimeout(args[i])
			if err != nil {
				return options{}, err
			}
			opts.sessionIdle = d
		case strings.HasPrefix(a, "--session-idle-timeout="):
			d, err := parseIdleTimeout(strings.TrimPrefix(a, "--session-idle-timeout="))
			if err != nil {
				return options{}, err
			}
			opts.sessionIdle = d
		case a == "--session-output-log-max":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a size, e.g. 64MB", a)
			}
			i++
			n, err := parseLogMax(args[i])
			if err != nil {
				return options{}, err
			}
			opts.outputLogMax = n
		case strings.HasPrefix(a, "--session-output-log-max="):
			n, err := parseLogMax(strings.TrimPrefix(a, "--session-output-log-max="))
			if err != nil {
				return options{}, err
			}
			opts.outputLogMax = n
		case a == "--session-send-timeout":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a duration", a)
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return options{}, fmt.Errorf("%s: %w", a, err)
			}
			if d < 0 {
				return options{}, fmt.Errorf("%s must not be negative", a)
			}
			opts.sessionSendTimeout = d
		case strings.HasPrefix(a, "--session-send-timeout="):
			d, err := time.ParseDuration(strings.TrimPrefix(a, "--session-send-timeout="))
			if err != nil {
				return options{}, fmt.Errorf("--session-send-timeout: %w", err)
			}
			if d < 0 {
				return options{}, fmt.Errorf("--session-send-timeout must not be negative")
			}
			opts.sessionSendTimeout = d
		case a == "--shell":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.shell = args[i]
		case strings.HasPrefix(a, "--shell="):
			opts.shell = strings.TrimPrefix(a, "--shell=")
		case a == "--as":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a nickname", a)
			}
			i++
			opts.as = args[i]
		case strings.HasPrefix(a, "--as="):
			opts.as = strings.TrimPrefix(a, "--as=")
		case a == "--no-wait":
			opts.noWait = true
		case a == "--detach":
			opts.detach = true
		case a == "--read-only":
			opts.readOnly = true
		case a == "--close-on-exit":
			opts.closeOnExit = true
		case a == "--allow-peer":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a peer id or nickname", a)
			}
			i++
			opts.allowPeer = append(opts.allowPeer, args[i])
		case strings.HasPrefix(a, "--allow-peer="):
			opts.allowPeer = append(opts.allowPeer, strings.TrimPrefix(a, "--allow-peer="))
		case a == "--max-sessions":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a number", a)
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return options{}, fmt.Errorf("%s must be a number, got %q", a, args[i])
			}
			opts.maxSessions = n
		case strings.HasPrefix(a, "--max-sessions="):
			n, err := strconv.Atoi(strings.TrimPrefix(a, "--max-sessions="))
			if err != nil || n < 0 {
				return options{}, fmt.Errorf("--max-sessions must be a number, got %q",
					strings.TrimPrefix(a, "--max-sessions="))
			}
			opts.maxSessions = n
		case a == "--verbose":
			opts.verbose = true
		case a == "--force":
			opts.force = true
		case a == "--fix":
			opts.fix = true
		case a == "--tls-cert":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.cert = args[i]
		case strings.HasPrefix(a, "--tls-cert="):
			opts.cert = strings.TrimPrefix(a, "--tls-cert=")
		case a == "--tls-key":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.key = args[i]
		case strings.HasPrefix(a, "--tls-key="):
			opts.key = strings.TrimPrefix(a, "--tls-key=")
		case a == "--live":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.live = args[i]
		case strings.HasPrefix(a, "--live="):
			opts.live = strings.TrimPrefix(a, "--live=")
		case a == "--dir":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.dir = args[i]
		case strings.HasPrefix(a, "--dir="):
			opts.dir = strings.TrimPrefix(a, "--dir=")
		case strings.HasPrefix(a, "-"):
			return options{}, fmt.Errorf("unknown flag %s", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		return opts, nil
	}
	opts.cmd = positional[0]
	opts.rest = positional[1:]
	return opts, nil
}

func colorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func parseLogMax(v string) (int64, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, fmt.Errorf("--session-output-log-max requires a size, e.g. 64MB")
	}
	upper := strings.ToUpper(s)
	mul := int64(1)
	switch {
	case strings.HasSuffix(upper, "GIB"):
		mul = 1 << 30
		upper = strings.TrimSuffix(upper, "GIB")
	case strings.HasSuffix(upper, "MIB"):
		mul = 1 << 20
		upper = strings.TrimSuffix(upper, "MIB")
	case strings.HasSuffix(upper, "KIB"):
		mul = 1 << 10
		upper = strings.TrimSuffix(upper, "KIB")
	case strings.HasSuffix(upper, "GB"):
		mul = 1 << 30
		upper = strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		mul = 1 << 20
		upper = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "KB"):
		mul = 1 << 10
		upper = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "G"):
		mul = 1 << 30
		upper = strings.TrimSuffix(upper, "G")
	case strings.HasSuffix(upper, "M"):
		mul = 1 << 20
		upper = strings.TrimSuffix(upper, "M")
	case strings.HasSuffix(upper, "K"):
		mul = 1 << 10
		upper = strings.TrimSuffix(upper, "K")
	}
	upper = strings.TrimSpace(upper)
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("--session-output-log-max %q: use a size like 64MB", v)
	}
	if n <= 0 {
		return 0, fmt.Errorf("--session-output-log-max must be positive")
	}
	out := n * mul
	if mul != 1 && out/mul != n {
		return 0, fmt.Errorf("--session-output-log-max %q: size overflows", v)
	}
	return out, nil
}
