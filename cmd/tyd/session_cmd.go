package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/peers"
	"tyd/internal/recent"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// finishStream turns the result of an attach or watch stream into a CLI exit
// status. When the shell exited, the daemon already streamed an explanatory
// notice, so all that is left is to record the session as exited (so
// `tyd session list` stays truthful) and report success: the session is still
// alive and re-attachable.
func finishStream(opts options, sessionID string, err error) error {
	if !client.IsShellExited(err) {
		return err
	}
	markSessionExited(opts, sessionID)
	return nil
}

// markSessionExited records EXITED in the local catalog, keeping the rest of
// the record as it is.
func markSessionExited(opts options, sessionID string) {
	if sessionID == "" {
		return
	}
	rec, ok := loadLocalCatalog(opts).Get(sessionID)
	if !ok {
		return
	}
	rec.State = string(session.StateExited)
	rememberSession(opts, rec)
}

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
		info, err := client.Create(ep, key, client.CreateOpts{Shell: opts.shell})
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, info.ID)
		rememberSession(opts, catalog.FromInfo(info, peerID, ep.Address, ep.CertFP, string(ep.Kind), ep.Candidates))
		markUsed(opts, peerID, info.ID)
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
		return finishStream(opts, info.ID, err)
	case "list":
		return runSessionList(opts)
	case "send":
		return runSessionSend(opts)
	case "read":
		return runSessionRead(opts)
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
		if err == nil {
			touchSession(opts, sid)
			markUsed(opts, peerID, sid)
		}
		return finishStream(opts, sid, err)
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
		if err == nil {
			touchSession(opts, sid)
			markUsed(opts, peerID, sid)
		}
		return finishStream(opts, sid, err)
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
			// The archive measures from the close, not from the last time the
			// catalog happened to be written.
			rec.ClosedAt = time.Now().UTC()
			rememberSession(opts, rec)
		}
		markUsed(opts, peerID, sid)
		return nil
	case "rm":
		return runSessionRemove(opts, firstArg(args))
	case "restore":
		return restoreSession(opts, firstArg(args))
	case "approve":
		if err := refuseIfInSession("session approve"); err != nil {
			return err
		}
		digest := approveDigestArg(args)
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
		info, err := client.Approve(local, key, sid, digest)
		if err != nil {
			return err
		}
		fmt.Println(info.ID)
		return nil
	case "reject":
		if err := refuseIfInSession("session reject"); err != nil {
			return err
		}
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

// peerNames maps peer id to the nickname the operator gave it. A missing or
// unreadable peers.json is not an error here: the list still renders, just with
// raw ids.
func peerNames(path string) map[string]string {
	doc, err := peers.Load(path)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(doc.Peers))
	for _, p := range doc.Peers {
		if p.Nickname != "" {
			out[p.ID] = p.Nickname
		}
	}
	return out
}

// peerLabel prefers the nickname, because the raw id is what `peer list`
// already shows in its own ID column. An unknown peer keeps its id rather than
// becoming "-", so the column never loses the one thing you can paste into
// `peer show`.
func peerLabel(peerID string, names map[string]string) string {
	if peerID == "" {
		return "-"
	}
	if n := names[peerID]; n != "" {
		return n
	}
	return peerID
}

func runSessionList(opts options) error {
	cat := loadLocalCatalog(opts)
	adoc, _ := alias.Load(opts.aliases)
	names := peerNames(opts.peers)
	items := cat.List()
	arch := loadArchive(opts)
	rows := make([]sessionListRow, 0, len(items))
	hidden := 0
	for _, it := range items {
		archived := arch.SessionArchived(it.ID)
		if archived && !opts.all {
			hidden++
			continue
		}
		an := ""
		if adoc != nil {
			an = adoc.NameFor(it.ID)
		}
		peer := peerLabel(it.PeerID, names)
		state := it.State
		if archived {
			state += " (archived)"
		}
		rows = append(rows, sessionListRow{
			ID: it.ID, Alias: an, Peer: peer,
			State: state, Created: catalog.CreatedDisplay(it),
		})
	}
	writeSessionList(os.Stdout, rows, colorEnabled(os.Stdout))
	// A hidden row still exists, and one that is only hidden may still be
	// attachable. Say how many are out of sight rather than let the list look
	// complete.
	if hidden > 0 {
		fmt.Fprintf(os.Stderr, "\n%d archived session(s) hidden; use --all to show them\n", hidden)
	}
	return nil
}

// errForceRequired marks the refusal that a destructive command returns instead
// of acting. It is a refusal, not a failure, so callers can tell the two apart.
var errForceRequired = errors.New("--force required")

// runSessionRemove drops a session from the local catalog.
//
// It refuses a session that is not closed, and --force does not change that: the
// row holds the endpoint, so a row removed while the session is live is a
// session this host can no longer reach. Closing it is what makes it reachable
// again, and closing is not something a flag should do behind the operator's
// back.
func runSessionRemove(opts options, ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("usage: tyd session rm <session_id|alias>")
	}
	sid, err := resolveSessionRef(opts, ref)
	if err != nil {
		return fmt.Errorf("usage: tyd session rm <session_id|alias>: %w", err)
	}
	cat := loadLocalCatalog(opts)
	rec, ok := cat.Get(sid)
	if !ok {
		return fmt.Errorf("unknown session %q (not in local catalog)", ref)
	}
	if !strings.EqualFold(rec.State, string(session.StateClosed)) {
		state := rec.State
		if strings.TrimSpace(state) == "" {
			state = "in an unknown state"
		}
		return fmt.Errorf("session %s is %s, not closed; close it first: tyd session close %s", sid, state, sid)
	}
	if !opts.force {
		return fmt.Errorf(`%w
  refusing to remove session %s from the local catalog
  the daemon keeps the session until it restarts; this only forgets it here
  any alias for it is removed with it, and the removal cannot be undone
  re-run with --force to remove it`, errForceRequired, sid)
	}

	if err := forgetSessions(opts, []string{sid}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed session %s from the local catalog\n", sid)
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
		warnDotName("session alias", args[1], "tyd session attach "+args[1])
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
		warnDotName("session alias", name, "tyd session attach "+name)
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

// approveDigestArg picks --digest out of the argument list.
//
// An approval is bound to one request, so with more than one waiting the operator
// has to say which. Without it the daemon refuses and lists them, rather than
// deciding the first one for them.
func approveDigestArg(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--digest" {
			return args[i+1]
		}
	}
	return ""
}
