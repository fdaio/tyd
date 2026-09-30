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
// The target is fixed at startup: --peer, or the only outbound peer, or the
// local daemon. recent.json is not consulted, because a server that followed
// the last machine a person typed would drive a target nobody chose for it.
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

func mcpTargetLabel(t mcpTarget) string {
	if t.nickname != "" {
		return fmt.Sprintf("%s (%s)", t.label, t.nickname)
	}
	return t.label
}

// mcpPeerLabels are the values a tool call may pass as peer.
//
// A local target has no name, so it stays empty and reads as "this machine". An
// explicit peer keeps the name the command line gave it: a description that
// listed the second target but not the first would be describing a choice the
// model cannot express.
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
	local := mcpTarget{}

	if len(opts.allowPeer) > 0 {
		seen := map[string]bool{}
		out := make([]mcpTarget, 0, len(opts.allowPeer))
		for _, ref := range opts.allowPeer {
			p, err := doc.Find(ref)
			if err != nil {
				return nil, fmt.Errorf("--allow-peer %q: %w", ref, err)
			}
			if seen[p.ID] {
				return nil, fmt.Errorf("--allow-peer names peer %q twice", ref)
			}
			seen[p.ID] = true
			out = append(out, mcpTarget{label: ref, peerID: p.ID, nickname: peerNickname(p)})
		}
		return out, nil
	}

	if opts.peer != "" {
		p, err := doc.Find(opts.peer)
		if err != nil {
			return nil, err
		}
		return []mcpTarget{{label: opts.peer, peerID: p.ID, nickname: peerNickname(p)}}, nil
	}

	outbound := doc.Outbound()
	switch len(outbound) {
	case 0:
		return []mcpTarget{local}, nil
	case 1:
		p := outbound[0]
		nick := peerNickname(&p)
		if nick == "" {
			nick = p.ID
		}
		return []mcpTarget{{label: nick, peerID: p.ID, nickname: nick}}, nil
	default:
		return nil, fmt.Errorf("this machine has %d outbound peers (%s); "+
			"name one with --peer, or list them with --allow-peer",
			len(outbound), strings.Join(peerRefs(outbound), ", "))
	}
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
