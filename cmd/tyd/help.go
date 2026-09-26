package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"tyd/internal/paths"
	"tyd/internal/recent"
)

type helpRow struct {
	name string
	desc string
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
	fmt.Fprintln(w, "Sessions:")
	writeHelpRows(w, []helpRow{
		{"session create", "Create a session and attach (use --detach for id only)"},
		{"session list", "List local sessions (alive first, newest first)"},
		{"session attach", "Attach to a session (id, alias, or recent)"},
		{"session watch", "Follow session output (read-only)"},
		{"session approve", "Approve a PENDING remote session (local unix)"},
		{"session reject", "Reject a PENDING remote session (local unix)"},
		{"session close", "Close a session (kept as history)"},
		{"session alias", "Name a session for later attach/watch/close"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Peers:")
	writeHelpRows(w, []helpRow{
		{"peer list", "List paired peers"},
		{"peer show", "Show peer detail, endpoint, and reachability"},
		{"peer alias", "Set or clear a peer nickname"},
		{"revoke", "Revoke a paired peer (either side)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Pairing:")
	writeHelpRows(w, []helpRow{
		{"keygen", "Generate Ed25519 identity (optional; also auto-created)"},
		{"register", "Register with Control Panel (--force replaces)"},
		{"invite", "Mint invite; print tyd accept … and wait (10m TTL)"},
		{"accept", "Accept a peer invite (token or pasted accept line)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Daemon:")
	writeHelpRows(w, []helpRow{
		{"up", "Start the tyd daemon (unix socket; TLS off by default)"},
		{"status", "Show CP registration, peers, and connections"},
		{"approval", "Show or set approval mode (full|pre|post)"},
		{"doctor", "Check state files and disk; --fix rebuilds peers.json"},
		{"serve", "Deprecated alias for up"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  Connection:")
	writeHelpRows(w, []helpRow{
		{"--socket PATH", fmt.Sprintf("Unix socket (default %s)", paths.DefaultSocket())},
		{"--listen ADDR|off", fmt.Sprintf("Manual TLS listen for up (default %s)", paths.DefaultListen())},
		{"--data-listen MODE", "Data-plane QUIC: auto|off|HOST:PORT (default auto)"},
		{"--advertise HOST", "Host to prefer in CP candidates (default: auto interface IPs)"},
		{"--addr HOST:PORT", "TLS client endpoint (local override)"},
		{"--peer ID|NICK", "Target paired peer for session commands"},
		{"--relay URL|off", fmt.Sprintf("Dual-NAT rendezvous (default %s; off disables)", paths.DefaultRelay())},
		{"--tls-cert PATH", fmt.Sprintf("Server cert / client pin (default %s)", paths.DefaultServerCert())},
		{"--tls-key PATH", "Server key"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Paths / identity:")
	writeHelpRows(w, []helpRow{
		{"--identity PATH", fmt.Sprintf("Client identity (default %s)", paths.DefaultIdentity())},
		{"--trust PATH", fmt.Sprintf("Trust file (default %s)", paths.DefaultTrust())},
		{"--peers PATH", fmt.Sprintf("Paired peers file (default %s)", paths.DefaultPeers())},
		{"--aliases PATH", fmt.Sprintf("Session aliases file (default %s)", paths.DefaultAliases())},
		{"--platform URL", fmt.Sprintf("Control Panel URL (default %s)", paths.DefaultPlatform())},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Behavior:")
	writeHelpRows(w, []helpRow{
		{"--approval MODE", "Register approval: full|pre|post (default full)"},
		{"--audit-log PATH", fmt.Sprintf("up: record control events as JSON lines (e.g. %s)", paths.DefaultAudit())},
		{"--session-idle-timeout", "up: close sessions idle this long, e.g. 8h (default off)"},
		{"--as NAME", "Peer nickname when accepting an invite"},
		{"--no-wait", "register/invite: exit after printing accept (no countdown)"},
		{"--detach", "session create: print id only (do not attach)"},
		{"--verbose", "session create/attach/watch: print connect debug (ssh -v style)"},
		{"--force", "register: replace existing registration (invalidates peers)"},
		{"--fix", "doctor: rebuild a damaged peers.json from the Control Panel"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  Connecting: Ctrl-C cancels; attached: Ctrl-\\ detaches; watch: Ctrl-C/\\ stops.")
	fmt.Fprintln(w, "  Use --peer <id|nickname> for create/attach/watch/close on a paired peer.")
	fmt.Fprintln(w, "  session list is local only; it does not use --peer or CP.")
	fmt.Fprintln(w, "  register/invite wait by default; --no-wait skips; Ctrl-C revokes the invite.")
	fmt.Fprintln(w, "  Omit session id to reuse the most recent session (recent.json).")
	fmt.Fprintln(w, "  Pairing: see docs/requirements/control-plane-pairing.md")
}

func writeSessionHelp(w io.Writer, color bool) {
	ph := recent.SessionPlaceholder(paths.DefaultRecent())
	attachEx := "attach [session_id|alias]"
	if ph != "" {
		attachEx = "attach [" + ph + "]"
	}
	fmt.Fprintln(w, "Manage persistent PTY sessions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd session [command]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	writeHelpRows(w, []helpRow{
		{"create", "Create and attach (interactive; Ctrl-\\ detaches)"},
		{"list", "List local sessions (alive first, newest first)"},
		{"attach", "Attach (id, alias, or omit for recent)"},
		{"watch", "Follow output (id, alias, or omit for recent)"},
		{"approve", "Approve PENDING session (local unix only)"},
		{"reject", "Reject PENDING session (local unix only)"},
		{"close", "Close a session (kept as history)"},
		{"alias", "Name a session for later attach/watch/close"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintf(w, "  %-24s Interactive; Ctrl-\\ detaches.\n", attachEx)
	fmt.Fprintln(w, "  create --detach          Print session id only (for scripts).")
	fmt.Fprintln(w, "  --verbose                SSH-style connect debug on stderr.")
	fmt.Fprintln(w, "  watch [session_id|alias]  Read-only follow; banner + type-ignored hint.")
	fmt.Fprintln(w, "  approve [id|alias]        Start PTY for a PENDING remote create.")
	fmt.Fprintln(w, "  reject [id|alias]         Remove a PENDING session.")
	fmt.Fprintln(w, "  close [id|alias]          Marks CLOSED; kept until daemon restart.")
	fmt.Fprintln(w, "  Omit the id to reuse the most recent session (recent.json).")
	fmt.Fprintln(w, "  --peer <id|nick>          Target a paired peer for dialing commands.")
	fmt.Fprintln(w, "  session list              Local catalog only (no CP / daemon).")
	fmt.Fprintln(w, "  alias <name>              Name the recent session for later use.")
	fmt.Fprintln(w, "  alias list | alias rm     List or remove session aliases.")
}

func sessionUsage() string {
	var b strings.Builder
	writeSessionHelp(&b, false)
	return b.String()
}

func sessionCommands() []string {
	return []string{"create", "list", "attach", "watch", "approve", "reject", "close", "alias", "help"}
}

func rootCommands() []string {
	return []string{"keygen", "up", "serve", "register", "invite", "accept", "revoke", "status", "alias", "session", "peer", "approval", "doctor", "help"}
}

func peerCommands() []string {
	return []string{"list", "show", "alias", "help"}
}

func unknownCommandErr(kind, got string, candidates []string, usage string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown %s %q", kind, got)
	if s := suggestCommand(got, candidates); s != "" {
		fmt.Fprintf(&b, "\n\nDid you mean %q?", s)
	}
	if usage != "" {
		fmt.Fprintf(&b, "\n\n%s", strings.TrimRight(usage, "\n"))
	}
	return fmt.Errorf("%s", b.String())
}

func usage() {
	writeRootHelp(os.Stderr, colorEnabled(os.Stderr))
}
