package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"golang.org/x/term"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/paths"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

const (
	ansiCyan   = "\033[36m"
	ansiReset  = "\033[0m"
	helpColPad = 22
)

type helpRow struct {
	name string
	desc string
}

type options struct {
	socket   string
	listen   string
	addr     string
	identity string
	trust    string
	cert     string
	key      string
	cmd      string
	rest     []string
}

func main() {
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

func endpoint(opts options) client.Endpoint {
	if opts.addr != "" {
		return client.Endpoint{
			Kind:     transport.KindTLS,
			Address:  opts.addr,
			CertPath: opts.cert,
		}
	}
	return client.Endpoint{
		Kind:    transport.KindUnix,
		Address: opts.socket,
	}
}

func run(opts options) error {
	switch opts.cmd {
	case "keygen":
		return runKeygen(opts)
	case "serve":
		return runServe(opts)
	case "status":
		return runStatus(opts)
	case "session":
		return runSession(opts)
	case "create", "list", "attach", "close":
		return fmt.Errorf("unknown command %q; use: tyd session %s", opts.cmd, opts.cmd)
	default:
		return fmt.Errorf("unknown command %q", opts.cmd)
	}
}

func runSession(opts options) error {
	if len(opts.rest) == 0 {
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	switch sub {
	case "create":
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		info, err := client.Create(endpoint(opts), key, client.CreateOpts{})
		if err != nil {
			return err
		}
		fmt.Println(info.ID)
		return nil
	case "list":
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		items, err := client.List(endpoint(opts), key)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SESSION\tPID\tSTATE\tSIZE\tCREATED")
		for _, it := range items {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%dx%d\t%s\n", it.ID, it.PID, it.State, it.Cols, it.Rows, it.CreatedAt)
		}
		return tw.Flush()
	case "attach":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd session attach <session_id>")
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "attached to %s  detach: Ctrl-\\\n", args[0])
		return client.Attach(endpoint(opts), key, args[0], os.Stdin, os.Stdout)
	case "watch":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd session watch <session_id>")
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "watching %s  exit: Ctrl-C or Ctrl-\\\n", args[0])
		return client.Watch(endpoint(opts), key, args[0], os.Stdout)
	case "close":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd session close <session_id>")
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		return client.CloseSession(endpoint(opts), key, args[0])
	case "help", "-h", "--help":
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	default:
		return fmt.Errorf("unknown session command %q\n%s", sub, sessionUsage())
	}
}

func runStatus(opts options) error {
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	items, err := client.Status(endpoint(opts), key)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTRANSPORT\tREMOTE\tTLS\tSTATE\tPRINCIPAL\tSESSION\tSINCE")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\n",
			it.ID, it.Transport, it.RemoteAddr, it.TLS, it.State, it.Principal, it.SessionID, it.EstablishedAt)
	}
	return tw.Flush()
}

func loadIdentity(path string) (ed25519.PrivateKey, error) {
	key, err := auth.LoadIdentity(path)
	if err != nil {
		return nil, fmt.Errorf("load identity %s: %w (run 'tyd keygen')", path, err)
	}
	return key, nil
}

func runKeygen(opts options) error {
	if _, err := os.Stat(opts.identity); err == nil {
		return fmt.Errorf("identity already exists: %s", opts.identity)
	}
	_, priv, err := auth.Generate()
	if err != nil {
		return err
	}
	if err := auth.WriteIdentity(opts.identity, priv); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr, "wrote %s\n", opts.identity)
	if _, err := os.Stat(opts.trust); os.IsNotExist(err) {
		if err := auth.WriteBootstrapTrust(opts.trust, "local", pub); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (list+create for this key)\n", opts.trust)
	}
	fmt.Println(auth.EncodePublic(pub))
	return nil
}

func runServe(opts options) error {
	trust, err := auth.LoadStore(opts.trust)
	if err != nil {
		return fmt.Errorf("load trust %s: %w (run 'tyd keygen')", opts.trust, err)
	}
	mgr := session.NewManager()
	srv := server.NewWithConfig(server.Config{
		Socket:   opts.socket,
		Listen:   opts.listen,
		CertPath: opts.cert,
		KeyPath:  opts.key,
		Mgr:      mgr,
		Trust:    trust,
	})
	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd listening unix %s\n", opts.socket)
	if opts.listen != "" && opts.listen != "off" {
		fmt.Fprintf(os.Stderr, "tyd listening tls  %s (cert fp %s)\n", opts.listen, srv.TLSFingerprint())
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	return srv.Close()
}

func parseArgs(args []string) (options, error) {
	opts := options{
		socket:   paths.DefaultSocket(),
		listen:   paths.DefaultListen(),
		identity: paths.DefaultIdentity(),
		trust:    paths.DefaultTrust(),
		cert:     paths.DefaultServerCert(),
		key:      paths.DefaultServerKey(),
	}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
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
		case a == "--addr":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires host:port", a)
			}
			i++
			opts.addr = args[i]
		case strings.HasPrefix(a, "--addr="):
			opts.addr = strings.TrimPrefix(a, "--addr=")
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

func writeHelpRows(w io.Writer, rows []helpRow, color bool) {
	for _, r := range rows {
		name := r.name
		pad := helpColPad - len(name)
		if pad < 2 {
			pad = 2
		}
		if color {
			fmt.Fprintf(w, "  %s%s%s%s%s\n", ansiCyan, name, ansiReset, strings.Repeat(" ", pad), r.desc)
			continue
		}
		fmt.Fprintf(w, "  %-*s%s\n", helpColPad, name, r.desc)
	}
}

func writeRootHelp(w io.Writer, color bool) {
	fmt.Fprintln(w, "Persistent, remotely attachable terminal sessions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd [command] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Common commands:")
	writeHelpRows(w, []helpRow{
		{"session create", "Create a persistent PTY session"},
		{"session list", "List sessions (alive first)"},
		{"session attach", "Attach to a running session"},
		{"session watch", "Follow session output (read-only)"},
		{"session close", "Close a session (kept as history)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Identity:")
	writeHelpRows(w, []helpRow{
		{"keygen", "Generate Ed25519 client identity"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Daemon:")
	writeHelpRows(w, []helpRow{
		{"serve", "Start the tyd daemon"},
		{"status", "Show daemon / connection status"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	writeHelpRows(w, []helpRow{
		{"--socket PATH", fmt.Sprintf("Unix socket (default %s)", paths.DefaultSocket())},
		{"--listen ADDR|off", fmt.Sprintf("TLS listen for serve (default %s)", paths.DefaultListen())},
		{"--addr HOST:PORT", "TLS client endpoint"},
		{"--identity PATH", fmt.Sprintf("Client identity (default %s)", paths.DefaultIdentity())},
		{"--trust PATH", fmt.Sprintf("Trust file (default %s)", paths.DefaultTrust())},
		{"--tls-cert PATH", fmt.Sprintf("Server cert / client pin (default %s)", paths.DefaultServerCert())},
		{"--tls-key PATH", "Server key"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  While attached, Ctrl-\\ detaches; the shell keeps running.")
	fmt.Fprintln(w, "  While watching, Ctrl-C or Ctrl-\\ stops; the session is not closed.")
}

func writeSessionHelp(w io.Writer, color bool) {
	fmt.Fprintln(w, "Manage persistent PTY sessions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd session [command]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	writeHelpRows(w, []helpRow{
		{"create", "Create a persistent PTY session"},
		{"list", "List sessions (alive first)"},
		{"attach", "Attach to a running session"},
		{"watch", "Follow session output (read-only)"},
		{"close", "Close a session (kept as history)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  attach <session_id>   Interactive; Ctrl-\\ detaches.")
	fmt.Fprintln(w, "  watch <session_id>    Read-only; Ctrl-C / Ctrl-\\ stops.")
	fmt.Fprintln(w, "  close <session_id>    Marks CLOSED; kept until daemon restart.")
}

func sessionUsage() string {
	var b strings.Builder
	writeSessionHelp(&b, false)
	return b.String()
}

func usage() {
	writeRootHelp(os.Stderr, colorEnabled(os.Stderr))
}
