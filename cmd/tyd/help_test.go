package main

import (
	"bytes"
	"strings"
	"testing"
)

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
