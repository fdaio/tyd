package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/recent"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func runSession(opts options) error {
	if len(opts.rest) == 0 {
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	st := newConnectStatus(os.Stderr, opts.verbose)
	switch sub {
	case "create":
		st.Log("Resolving endpoint.")
		ep, peerID, err := endpoint(opts)
		if err != nil {
			st.Clear()
			return err
		}
		if err := ensureLocalDaemon(opts, ep); err != nil {
			st.Clear()
			return err
		}
		bindSessionProgress(&ep, st)
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		info, err := client.Create(ep, key, client.CreateOpts{})
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, info.ID)
		rememberSession(opts, catalog.FromInfo(info, peerID, ep.Address, ep.CertFP, string(ep.Kind), ep.Candidates))
		if info.State == string(session.StatePending) {
			st.Clear()
			fmt.Fprintln(os.Stderr, "pending approval")
			fmt.Println(info.ID)
			return nil
		}
		if opts.detach {
			st.Clear()
			fmt.Println(info.ID)
			return nil
		}
		err = client.Attach(ep, key, info.ID, os.Stdin, os.Stdout)
		st.Clear()
		return err
	case "list":
		return runSessionList(opts)
	case "attach":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session attach [session_id|alias]: %w", err)
		}
		st.Log("Resolving endpoint.")
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			st.Clear()
			return err
		}
		if err := ensureLocalDaemon(opts, ep); err != nil {
			st.Clear()
			return err
		}
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, st, sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			return client.Attach(ep, key, sid, os.Stdin, os.Stdout)
		})
		st.Clear()
		return err
	case "watch":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session watch [session_id|alias]: %w", err)
		}
		st.Log("Resolving endpoint.")
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			st.Clear()
			return err
		}
		if err := ensureLocalDaemon(opts, ep); err != nil {
			st.Clear()
			return err
		}
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, st, sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			bindWatchProgress(&ep, st)
			return client.Watch(ep, key, sid, os.Stdin, os.Stdout)
		})
		st.Clear()
		return err
	case "close":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session close [session_id|alias]: %w", err)
		}
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			return err
		}
		if err := ensureLocalDaemon(opts, ep); err != nil {
			return err
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, newConnectStatus(os.Stderr, false), sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			return client.CloseSession(ep, key, sid)
		})
		if err != nil {
			return err
		}
		if rec, ok := loadLocalCatalog(opts).Get(sid); ok {
			rec.State = string(session.StateClosed)
			rememberSession(opts, rec)
		}
		return nil
	case "approve":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session approve [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		local := client.Endpoint{Kind: transport.KindUnix, Address: opts.socket}
		if err := ensureLocalDaemon(opts, local); err != nil {
			return err
		}
		info, err := client.Approve(local, key, sid)
		if err != nil {
			return err
		}
		fmt.Println(info.ID)
		return nil
	case "reject":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session reject [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		local := client.Endpoint{Kind: transport.KindUnix, Address: opts.socket}
		if err := ensureLocalDaemon(opts, local); err != nil {
			return err
		}
		return client.Reject(local, key, sid)
	case "alias":
		aliasOpts := opts
		aliasOpts.rest = args
		return runAlias(aliasOpts)
	case "help", "-h", "--help":
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	default:
		return unknownCommandErr("session command", sub, sessionCommands(), sessionUsage())
	}
}

func runSessionList(opts options) error {
	cat := loadLocalCatalog(opts)
	adoc, _ := alias.Load(opts.aliases)
	items := cat.List()
	rows := make([]sessionListRow, 0, len(items))
	for _, it := range items {
		an := ""
		if adoc != nil {
			an = adoc.NameFor(it.ID)
		}
		peer := it.PeerID
		if peer == "" {
			peer = "-"
		}
		rows = append(rows, sessionListRow{
			ID: it.ID, Alias: an, Peer: peer,
			State: it.State, Created: catalog.CreatedDisplay(it),
		})
	}
	writeSessionList(os.Stdout, rows, colorEnabled(os.Stdout))
	return nil
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func runAlias(opts options) error {
	doc, err := alias.Load(opts.aliases)
	if err != nil {
		return err
	}
	if len(opts.rest) == 0 || opts.rest[0] == "list" {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ALIAS\tSESSION\tPEER")
		for _, e := range doc.Aliases {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.SessionID, e.PeerID)
		}
		return tw.Flush()
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	switch sub {
	case "rm", "remove", "unset":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd session alias rm <name>")
		}
		if err := doc.Remove(args[0]); err != nil {
			return err
		}
		return alias.Save(opts.aliases, doc)
	case "set":
		if len(args) != 2 {
			return fmt.Errorf("usage: tyd session alias set <session_id|alias> <name>")
		}
		sid, err := resolveSessionIDForAlias(opts, args[0])
		if err != nil {
			return err
		}
		if err := validateAliasNameAgainstCatalog(opts, args[1]); err != nil {
			return err
		}
		peerID := ""
		if rec, _ := recent.Load(opts.recent); rec != nil {
			peerID = rec.PeerID
		}
		if cat, err := catalog.Load(sessionsPath(opts)); err == nil {
			if r, ok := cat.Get(sid); ok && r.PeerID != "" {
				peerID = r.PeerID
			}
		}
		if err := doc.Set(args[1], sid, peerID); err != nil {
			return err
		}
		if err := alias.Save(opts.aliases, doc); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", args[1], sid)
		return nil
	default:
		// tyd alias <name>                 — alias the recent session
		// tyd alias <session_id> <name>    — alias an explicit session
		var sid, name string
		switch len(opts.rest) {
		case 1:
			name = opts.rest[0]
			var err error
			sid, err = resolveSessionIDForAlias(opts, "")
			if err != nil {
				return fmt.Errorf("usage: tyd session alias <name> (needs a recent session), or tyd session alias <session_id> <name>: %w", err)
			}
		case 2:
			var err error
			sid, err = resolveSessionIDForAlias(opts, opts.rest[0])
			if err != nil {
				return err
			}
			name = opts.rest[1]
		default:
			return fmt.Errorf("usage: tyd session alias [<session_id>] <name> | tyd session alias list | tyd session alias rm <name>")
		}
		if err := validateAliasNameAgainstCatalog(opts, name); err != nil {
			return err
		}
		peerID := ""
		if rec, _ := recent.Load(opts.recent); rec != nil {
			peerID = rec.PeerID
		}
		if cat, err := catalog.Load(sessionsPath(opts)); err == nil {
			if r, ok := cat.Get(sid); ok && r.PeerID != "" {
				peerID = r.PeerID
			}
		}
		if err := doc.Set(name, sid, peerID); err != nil {
			return err
		}
		if err := alias.Save(opts.aliases, doc); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", name, sid)
		return nil
	}
}

type sessionListRow struct {
	ID, Alias, Peer, State, Created string
}

func liveState(state string) bool {
	return strings.EqualFold(strings.TrimSpace(state), "ATTACHED")
}

func padCell(s string, width int) string {
	if width < len(s) {
		width = len(s)
	}
	return fmt.Sprintf("%-*s", width, s)
}

func paintCell(s string, width int, color bool) string {
	padded := padCell(s, width)
	if !color {
		return padded
	}
	return ansiCyan + padded + ansiReset
}

func writeSessionList(w io.Writer, rows []sessionListRow, color bool) {
	idW, aliasW, peerW, stateW, createdW := len("SESSION"), len("ALIAS"), len("PEER"), len("STATE"), len("CREATED")
	for _, r := range rows {
		idW = max(idW, len(r.ID))
		aliasW = max(aliasW, len(r.Alias))
		peerW = max(peerW, len(r.Peer))
		stateW = max(stateW, len(r.State))
		createdW = max(createdW, len(r.Created))
	}
	const gap = "  "
	fmt.Fprint(w, padCell("SESSION", idW), gap)
	fmt.Fprint(w, padCell("ALIAS", aliasW), gap)
	fmt.Fprint(w, padCell("PEER", peerW), gap)
	fmt.Fprint(w, padCell("STATE", stateW), gap)
	fmt.Fprintln(w, padCell("CREATED", createdW))
	for _, r := range rows {
		fmt.Fprint(w, padCell(r.ID, idW), gap)
		fmt.Fprint(w, paintCell(r.Alias, aliasW, color && r.Alias != ""), gap)
		fmt.Fprint(w, padCell(r.Peer, peerW), gap)
		fmt.Fprint(w, paintCell(r.State, stateW, color && liveState(r.State)), gap)
		fmt.Fprintln(w, padCell(r.Created, createdW))
	}
}
