package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/paths"
	"tyd/internal/server"
	"tyd/internal/session"
)

type options struct {
	socket   string
	identity string
	trust    string
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

func run(opts options) error {
	switch opts.cmd {
	case "keygen":
		return runKeygen(opts)
	case "serve":
		return runServe(opts)
	case "create":
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		info, err := client.Create(opts.socket, key, client.CreateOpts{})
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
		items, err := client.List(opts.socket, key)
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
		if len(opts.rest) != 1 {
			return fmt.Errorf("usage: tyd attach <session_id>")
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "attached to %s  detach: Ctrl-\\\n", opts.rest[0])
		return client.Attach(opts.socket, key, opts.rest[0], os.Stdin, os.Stdout)
	case "close":
		if len(opts.rest) != 1 {
			return fmt.Errorf("usage: tyd close <session_id>")
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		return client.CloseSession(opts.socket, key, opts.rest[0])
	default:
		return fmt.Errorf("unknown command %q", opts.cmd)
	}
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
	srv := server.New(opts.socket, mgr, trust)
	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd listening on %s\n", opts.socket)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	return srv.Close()
}

func parseArgs(args []string) (options, error) {
	opts := options{
		socket:   paths.DefaultSocket(),
		identity: paths.DefaultIdentity(),
		trust:    paths.DefaultTrust(),
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

func usage() {
	fmt.Fprintf(os.Stderr, `tyd - persistent terminal session daemon

Usage:
  tyd [--socket PATH] [--identity PATH] [--trust PATH] keygen
  tyd [--socket PATH] [--trust PATH] serve
  tyd [--socket PATH] [--identity PATH] create
  tyd [--socket PATH] [--identity PATH] list
  tyd [--socket PATH] [--identity PATH] attach <session_id>
  tyd [--socket PATH] [--identity PATH] close  <session_id>

Default socket:   %s
Default identity: %s
Default trust:    %s
While attached, press Ctrl-\ to detach. The shell keeps running.
`, paths.DefaultSocket(), paths.DefaultIdentity(), paths.DefaultTrust())
}
