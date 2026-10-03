package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"tyd/internal/client"
	"tyd/internal/mcp"
	"tyd/internal/peers"
	"tyd/internal/transport"
)

// runMCP serves tyd sessions to a model over MCP on stdio.
//
// The target is fixed at startup: --peer, --allow-peer, or the only outbound
// peer. recent.json is not consulted, because a server that followed the last
// machine a person typed would drive a target nobody chose for it. A machine
// with no outbound peer is an error rather than a silent local target: the
// daemon on this machine holds the shells the operator is sitting at, so
// reaching for it has to be written down.
func runMCP(opts options) error {
	if len(opts.rest) > 0 {
		if opts.rest[0] == "help" {
			writeMCPHelp(os.Stderr, colorEnabled(os.Stderr))
			return nil
		}
		return fmt.Errorf("usage: tyd mcp [flags]\n\n%s", strings.TrimRight(mcpUsage(), "\n"))
	}
	if len(opts.allowPeer) > 0 && opts.peer != "" {
		return fmt.Errorf("--peer and --allow-peer are both given; --allow-peer already names the target")
	}
	if opts.maxSessions < 0 {
		return fmt.Errorf("--max-sessions must not be negative")
	}
	targets, err := mcpTargets(opts)
	if err != nil {
		return err
	}

	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}

	// Start the local daemon before the client connects. Reporting this after
	// the first tool call would arrive as a refused call instead.
	for _, t := range targets {
		if t.peerID != "" {
			continue
		}
		if err := ensureLocalDaemon(opts, client.Endpoint{Kind: transport.KindUnix, Address: opts.socket}); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(targets))
	for _, t := range targets {
		names = append(names, mcpTargetLabel(t))
	}
	fmt.Fprintf(os.Stderr, "tyd mcp: serving %s%s\n", strings.Join(names, ", "), mcpModeNote(opts))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return mcp.Serve(ctx, os.Stdin, os.Stdout, newMCPBackend(opts, key, targets), os.Stderr,
		mcp.Options{
			ReadOnly:    opts.readOnly,
			Peers:       mcpPeerLabels(targets),
			MaxSessions: opts.maxSessions,
			CloseOnExit: opts.closeOnExit,
			// From this machine's own resolved option, never from anything a caller
			// says. It decides whether the file tools exist in tools/list at all.
			FileRootConfigured: opts.fileRoot != "",
		})
}

func mcpModeNote(opts options) string {
	switch {
	case opts.readOnly:
		return " (read-only: only session_list and session_read are registered)"
	case opts.closeOnExit:
		return " (sessions opened here are closed on exit)"
	default:
		return ""
	}
}

// mcpTargetLabel names a machine for a person reading stderr. A peer given by a
// name other than its nickname carries both, so the operator can see which of
// their peers a shorthand meant.
func mcpTargetLabel(t mcpTarget) string {
	if t.nickname != "" && t.nickname != t.label {
		return fmt.Sprintf("%s (%s)", t.label, t.nickname)
	}
	return t.label
}

// mcpPeerLabels are the values a tool call may pass as peer.
//
// Every target is named, so the list a model chooses from is the list of real
// machines and not a mixture of names and blanks. A description that listed the
// second target but not the first would be describing a choice the model cannot
// express.
func mcpPeerLabels(targets []mcpTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.label)
	}
	return out
}

// mcpTargets resolves the command line into the machines this process serves.
func mcpTargets(opts options) ([]mcpTarget, error) {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return nil, err
	}

	if len(opts.allowPeer) > 0 {
		seen := map[string]bool{}
		out := make([]mcpTarget, 0, len(opts.allowPeer))
		for _, ref := range opts.allowPeer {
			t, err := resolveMCPTarget(doc, ref)
			if err != nil {
				return nil, fmt.Errorf("--allow-peer %q: %w", ref, err)
			}
			// Keyed on the machine, not on the spelling: the same peer named
			// twice is one target offered to a model as two, and the local
			// daemon is spelled like any other.
			if seen[t.peerID] {
				return nil, fmt.Errorf("--allow-peer names %s twice", mcpTargetLabel(t))
			}
			seen[t.peerID] = true
			out = append(out, t)
		}
		return out, nil
	}

	if opts.peer != "" {
		t, err := resolveMCPTarget(doc, opts.peer)
		if err != nil {
			return nil, err
		}
		return []mcpTarget{t}, nil
	}

	// A machine with no outbound peer does not mean the local daemon. That
	// daemon holds the shells the operator is sitting at, and it is not subject
	// to a pre-approval prompt, so falling back to it would put a model's
	// keystrokes there while the operator believed the target was elsewhere.
	// --peer local asks for this machine by name.
	outbound := doc.Outbound()
	switch len(outbound) {
	case 0:
		return nil, fmt.Errorf("this machine has no outbound peers; name the target with --peer <id|nick>, "+
			"or --peer %s for the daemon on this machine", mcpLocalRef)
	case 1:
		p := outbound[0]
		nick := peerNickname(&p)
		return []mcpTarget{{label: nick, peerID: p.ID, nickname: nick}}, nil
	default:
		return nil, fmt.Errorf("this machine has %d outbound peers (%s); name one with --peer, "+
			"pass --peer %s for the daemon on this machine, or list them with --allow-peer",
			len(outbound), strings.Join(peerRefs(outbound), ", "), mcpLocalRef)
	}
}

// resolveMCPTarget names a machine: the daemon on this one, or a paired peer.
//
// The reserved word is resolved first, so a peer that somehow holds the name
// cannot answer for the machine the word names. That ordering is the whole
// point of the reservation: an operator who wrote --peer local was choosing this
// machine, and a peer stealing the name would send a model's commands somewhere
// else while the label kept saying local. A peer with that nickname is still
// reachable, by its id, and the error says so rather than leaving the operator
// to work out why a name they can see in peer list does not resolve.
func resolveMCPTarget(doc *peers.File, ref string) (mcpTarget, error) {
	// --allow-peer= and --allow-peer "" both arrive here as an empty name, which
	// is not a target anybody can dial. Saying so beats letting it fall through
	// to the lookup and report that "" is not a peer.
	if strings.TrimSpace(ref) == "" {
		return mcpTarget{}, fmt.Errorf("empty target name; pass a peer id, a nickname, or %s", mcpLocalRef)
	}
	if ref == mcpLocalRef {
		if p, err := doc.Find(ref); err == nil {
			return mcpTarget{}, fmt.Errorf("--peer %s is this machine's own daemon, and a paired peer "+
				"(%s) answers to that name too; address the peer by its id, or give it another "+
				"nickname with tyd peer alias", mcpLocalRef, p.ID)
		}
		return mcpTarget{label: mcpLocalRef}, nil
	}
	if p, err := doc.Find(ref); err == nil {
		return mcpTarget{label: ref, peerID: p.ID, nickname: peerNickname(p)}, nil
	}
	return mcpTarget{}, fmt.Errorf("not a paired peer on this machine, and not %q; "+
		"run tyd peer list, or pass --peer %s for this machine", ref, mcpLocalRef)
}

func peerNickname(p *peers.Peer) string {
	if n := strings.TrimSpace(p.Nickname); n != "" {
		return n
	}
	return p.ID
}

// peerRefs lists peers by their shortest usable name, shortest first so the
// message reads well.
func peerRefs(list []peers.Peer) []string {
	out := make([]string, 0, len(list))
	for i := range list {
		out = append(out, peerNickname(&list[i]))
	}
	sort.Strings(out)
	return out
}
