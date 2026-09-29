package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpRowsNeverGlueNameToDesc(t *testing.T) {
	rows := []helpRow{
		{"--short", "desc"},
		{"--exactly-at-pad-width-xx", "desc"},
		{"--session-idle-timeout D", "up: close sessions idle this long"},
		{"--session-output-log-max SIZE", "up: per-session output log cap"},
		{"--live PATH", "up/doctor: live-agent state root"},
		{"a-very-long-flag-name-that-exceeds-the-column", "desc"},
	}
	for _, color := range []bool{false, true} {
		for _, r := range rows {
			var buf bytes.Buffer
			writeHelpRows(&buf, []helpRow{r}, color)
			line := strings.TrimRight(buf.String(), "\n")
			if color {
				line = strings.ReplaceAll(line, ansiCyan, "")
				line = strings.ReplaceAll(line, ansiReset, "")
			}
			line = strings.TrimPrefix(line, "  ")
			if !strings.HasPrefix(line, r.name) {
				t.Fatalf("color=%v: name mangled for %q: %q", color, r.name, line)
			}
			rest := line[len(r.name):]
			if rest == "" || strings.HasPrefix(rest, r.desc) {
				t.Fatalf("color=%v: name and desc glued for %q: %q", color, r.name, line)
			}
			if !strings.HasPrefix(strings.TrimLeft(rest, " "), r.desc) {
				t.Fatalf("color=%v: desc not separated for %q: %q", color, r.name, line)
			}
		}
	}
}

func TestRootHelpPlain(t *testing.T) {
	var buf bytes.Buffer
	writeRootHelp(&buf, false)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Fatalf("unexpected ANSI in plain help: %q", out)
	}
	for _, want := range []string{
		"Persistent, remotely attachable terminal sessions.",
		"Usage:",
		"tyd [command] [flags]",
		"Sessions:",
		"session create",
		"session list",
		"session attach",
		"<session>.<peer>",
		"tyd jammy.laptop",
		"session watch",
		"session approve",
		"session reject",
		"session close",
		"session alias",
		"Peers:",
		"peer list",
		"peer show",
		"peer alias",
		"revoke",
		"Pairing:",
		"keygen",
		"register",
		"invite",
		"accept",
		"Daemon:",
		"up",
		"serve",
		"status",
		"Flags:",
		"Connection:",
		"Paths / identity:",
		"Behavior:",
		"--socket PATH",
		"--peer ID|NICK",
		"--tls-cert PATH",
		"--aliases PATH",
		"--data-listen MODE",
		"--platform URL",
		"--session-output-log-max SIZE",
		"--force",
		"Tips:",
		"Ctrl-\\",
		"--peer",
		"recent",
		"control-plane-pairing.md",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRootHelpColor(t *testing.T) {
	var buf bytes.Buffer
	writeRootHelp(&buf, true)
	out := buf.String()
	if !strings.Contains(out, ansiCyan) || !strings.Contains(out, ansiReset) {
		t.Fatalf("expected ANSI cyan/reset in colored help: %q", out)
	}
	if !strings.Contains(out, "session create") {
		t.Fatal(out)
	}
}

func TestSessionHelpPlain(t *testing.T) {
	out := sessionUsage()
	if strings.Contains(out, "\033[") {
		t.Fatalf("unexpected ANSI in sessionUsage: %q", out)
	}
	for _, want := range []string{
		"Manage persistent PTY sessions.",
		"Usage:",
		"tyd session [command]",
		"Commands:",
		"create",
		"list",
		"attach",
		"watch",
		"approve",
		"reject",
		"close",
		"alias",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRootAndSessionCommandsIncludePeerAlias(t *testing.T) {
	root := rootCommands()
	foundPeer := false
	for _, c := range root {
		if c == "peer" {
			foundPeer = true
		}
	}
	if !foundPeer {
		t.Fatalf("rootCommands missing peer: %v", root)
	}
	sess := sessionCommands()
	foundAlias := false
	for _, c := range sess {
		if c == "alias" {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Fatalf("sessionCommands missing alias: %v", sess)
	}
}

func TestSessionHelpColor(t *testing.T) {

	var buf bytes.Buffer
	writeSessionHelp(&buf, true)
	out := buf.String()
	if !strings.Contains(out, ansiCyan) || !strings.Contains(out, ansiReset) {
		t.Fatalf("expected ANSI in colored session help: %q", out)
	}
}
