package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"tyd/internal/client"
	"tyd/internal/cpclient"
	"tyd/internal/peers"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func runPeer(opts options) error {
	if len(opts.rest) == 0 {
		writePeerHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	switch sub {
	case "list":
		return runPeerList(opts)
	case "show":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd peer show <id|alias>")
		}
		return runPeerShow(opts, args[0])
	case "alias":
		return runPeerAlias(opts, args)
	case "help", "-h", "--help":
		writePeerHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	default:
		return fmt.Errorf("unknown peer command %q\n\n%s", sub, peerUsage())
	}
}

func runPeerList(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tALIAS\tDIRECTION\tPAIRED")
	for _, p := range doc.Peers {
		nick := p.Nickname
		if nick == "" {
			nick = "-"
		}
		dir := p.Direction
		if dir == "" {
			dir = "-"
		}
		paired := "-"
		if !p.PairedAt.IsZero() {
			paired = p.PairedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, nick, dir, paired)
	}
	return tw.Flush()
}

func runPeerShow(opts options, idOrNick string) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	p, err := doc.Find(idOrNick)
	if err != nil {
		return err
	}

	nick := p.Nickname
	if nick == "" {
		nick = "-"
	}
	dir := p.Direction
	if dir == "" {
		dir = "-"
	}
	paired := "-"
	if !p.PairedAt.IsZero() {
		paired = p.PairedAt.UTC().Format(time.RFC3339)
	}

	writePeerShowFields(os.Stdout, p.ID, nick, dir, paired, shortKey(p.PublicKey))

	fmt.Println()
	fmt.Println("Endpoint")
	ep, epMeta, epErr := peerEndpointInfo(opts, p.ID)
	if epErr != nil {
		fmt.Printf("  (unavailable: %v)\n", epErr)
	} else {
		addrs := append([]string{ep.Address}, ep.Candidates...)
		fmt.Printf("  address:     %s\n", strings.Join(addrs, ", "))
		transportName := epMeta
		if transportName == "" {
			transportName = string(ep.Kind)
		}
		if transportName == "" {
			transportName = "tls"
		}
		fmt.Printf("  transport:   %s\n", transportName)
		fp := shortFP(ep.CertFP)
		if fp == "" {
			fp = "-"
		}
		fmt.Printf("  fingerprint: %s\n", fp)
	}

	fmt.Println()
	fmt.Println("Reachability")
	if epErr != nil {
		fmt.Println("  unreachable")
	} else if err := client.WaitReady(ep, 2*time.Second); err != nil {
		fmt.Println("  unreachable")
	} else {
		fmt.Println("  reachable")
	}

	alive, closed := 0, 0
	for _, rec := range loadLocalCatalog(opts).List() {
		if rec.PeerID != p.ID {
			continue
		}
		if strings.EqualFold(rec.State, string(session.StateClosed)) {
			closed++
		} else {
			alive++
		}
	}
	fmt.Println()
	fmt.Println("Sessions")
	fmt.Printf("  alive:  %d\n", alive)
	fmt.Printf("  closed: %d\n", closed)
	fmt.Printf("  total:  %d\n", alive+closed)
	return nil
}

func peerEndpointInfo(opts options, peerID string) (client.Endpoint, string, error) {
	platform, err := platformFor(opts)
	if err != nil {
		return client.Endpoint{}, "", err
	}
	cli := cpclient.New(platform)
	raw, err := cli.GetEndpointFull(peerID)
	if err != nil {
		return client.Endpoint{}, "", err
	}
	kind := transport.KindTLS
	transportName := "tls"
	if strings.EqualFold(raw.Transport, "quic") {
		kind = transport.KindQUIC
		transportName = "quic"
	} else if raw.Transport != "" {
		transportName = strings.ToLower(raw.Transport)
	}
	addrs := endpointDialOrder(raw)
	if len(addrs) == 0 {
		return client.Endpoint{}, "", fmt.Errorf("no dial candidates")
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    addrs[0],
		CertFP:     raw.CertFP,
		Candidates: addrs[1:],
	}, transportName, nil
}

func runPeerAlias(opts options, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tyd peer alias <id|nick> <name> | tyd peer alias rm <id|nick>")
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if args[0] == "rm" || args[0] == "remove" || args[0] == "unset" {
		if len(args) != 2 {
			return fmt.Errorf("usage: tyd peer alias rm <id|nick>")
		}
		p, err := doc.Find(args[1])
		if err != nil {
			return err
		}
		if err := doc.ClearNickname(p.ID); err != nil {
			return err
		}
		if err := peers.Save(opts.peers, doc); err != nil {
			return err
		}
		fmt.Printf("cleared alias for %s\n", p.ID)
		return nil
	}
	if len(args) != 2 {
		return fmt.Errorf("usage: tyd peer alias <id|nick> <name>")
	}
	p, err := doc.Find(args[0])
	if err != nil {
		return err
	}
	if err := doc.SetNickname(p.ID, args[1]); err != nil {
		return err
	}
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	fmt.Printf("%s -> %s\n", args[1], p.ID)
	return nil
}

func writePeerShowFields(w io.Writer, id, nick, dir, paired, key string) {
	fmt.Fprintf(w, "%-12s %s\n", "id:", id)
	fmt.Fprintf(w, "%-12s %s\n", "alias:", nick)
	fmt.Fprintf(w, "%-12s %s\n", "direction:", dir)
	fmt.Fprintf(w, "%-12s %s\n", "paired:", paired)
	fmt.Fprintf(w, "%-12s %s\n", "public key:", key)
}

func shortKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "-"
	}
	if len(key) > 16 {
		return key[:16] + "…"
	}
	return key
}

func writePeerHelp(w io.Writer, color bool) {
	fmt.Fprintln(w, "Manage paired peers and nicknames.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd peer [command]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	writeHelpRows(w, []helpRow{
		{"list", "List paired peers (id, alias, direction)"},
		{"show", "Show peer detail, endpoint, reachability"},
		{"alias", "Set a peer nickname (alias)"},
		{"alias rm", "Clear a peer nickname"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  tyd peer alias <id|nick> <name>  Nickname a peer for --peer targeting.")
	fmt.Fprintln(w, "  Use --peer <id|nick> on session dial commands (create/attach/watch/close).")
}

func peerUsage() string {
	var b strings.Builder
	writePeerHelp(&b, false)
	return b.String()
}
