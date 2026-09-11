package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"tyd/internal/client"
	"tyd/internal/paths"
	"tyd/internal/server"
	"tyd/internal/session"
)

func main() {
	socket, cmd, rest, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(2)
	}
	if cmd == "" || cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage()
		return
	}
	if err := run(socket, cmd, rest); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(socket, cmd string, rest []string) error {
	switch cmd {
	case "serve":
		return runServe(socket)
	case "create":
		info, err := client.Create(socket, client.CreateOpts{})
		if err != nil {
			return err
		}
		fmt.Println(info.ID)
		return nil
	case "list":
		items, err := client.List(socket)
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
		if len(rest) != 1 {
			return fmt.Errorf("usage: tyd attach <session_id>")
		}
		fmt.Fprintf(os.Stderr, "attached to %s  detach: Ctrl-\\\n", rest[0])
		return client.Attach(socket, rest[0], os.Stdin, os.Stdout)
	case "close":
		if len(rest) != 1 {
			return fmt.Errorf("usage: tyd close <session_id>")
		}
		return client.CloseSession(socket, rest[0])
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runServe(socket string) error {
	mgr := session.NewManager()
	srv := server.New(socket, mgr)
	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd listening on %s\n", socket)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	return srv.Close()
}

func parseArgs(args []string) (socket, cmd string, rest []string, err error) {
	socket = paths.DefaultSocket()
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			return socket, "help", nil, nil
		case a == "--socket" || a == "-socket":
			if i+1 >= len(args) {
				return "", "", nil, fmt.Errorf("%s requires a path", a)
			}
			i++
			socket = args[i]
		case strings.HasPrefix(a, "--socket="):
			socket = strings.TrimPrefix(a, "--socket=")
		case strings.HasPrefix(a, "-"):
			return "", "", nil, fmt.Errorf("unknown flag %s", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		return socket, "", nil, nil
	}
	return socket, positional[0], positional[1:], nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `tyd - persistent terminal session daemon

Usage:
  tyd [--socket PATH] serve
  tyd [--socket PATH] create
  tyd [--socket PATH] list
  tyd [--socket PATH] attach <session_id>
  tyd [--socket PATH] close  <session_id>

Default socket: %s
While attached, press Ctrl-\ to detach. The shell keeps running.
`, paths.DefaultSocket())
}
