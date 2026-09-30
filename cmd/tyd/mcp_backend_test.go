package main

import (
	"strings"
	"testing"

	"tyd/internal/peers"
)

func TestPeerLabelsNameEveryTarget(t *testing.T) {
	// An explicit peer keeps its name even when it is the default, because the
	// tool description offers these as the values a peer argument may take.
	got := mcpPeerLabels([]mcpTarget{{label: "laptop1"}, {label: "laptop2"}})
	if len(got) != 2 || got[0] != "laptop1" || got[1] != "laptop2" {
		t.Fatalf("labels = %v, want both peers named", got)
	}
	// The local daemon is named too. A list a model chooses from that mixed
	// names with blanks describes a choice it cannot express.
	got = mcpPeerLabels([]mcpTarget{{label: mcpLocalRef}, {label: "laptop"}})
	if len(got) != 2 || got[0] != "local" || got[1] != "laptop" {
		t.Fatalf("labels = %v, want every target named", got)
	}
}

func TestAllowPeerRefusesTheSameTargetTwice(t *testing.T) {
	doc := &peers.File{Peers: []peers.Peer{
		{ID: "p1", Nickname: "laptop"},
		{ID: "p2", Nickname: "server"},
	}}
	path := writePeers(t, doc)
	opts := options{peers: path, allowPeer: []string{"laptop", "p1"}}
	_, err := mcpTargets(opts)
	if err == nil {
		t.Fatal("naming the same peer twice must be refused")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error = %v, want it to say the peer was named twice", err)
	}
}

func TestAllowPeerKeepsTheGivenOrder(t *testing.T) {
	doc := &peers.File{Peers: []peers.Peer{
		{ID: "p1", Nickname: "laptop"},
		{ID: "p2", Nickname: "server"},
	}}
	path := writePeers(t, doc)
	// The first target is the default, so the order the command line gave is the
	// order a model should see.
	opts := options{peers: path, allowPeer: []string{"server", "laptop"}}
	targets, err := mcpTargets(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].label != "server" || targets[1].label != "laptop" {
		t.Fatalf("targets = %+v, want the command line order kept", targets)
	}
}

func writePeers(t *testing.T, doc *peers.File) string {
	t.Helper()
	path := t.TempDir() + "/peers.json"
	if err := peers.Save(path, doc); err != nil {
		t.Fatal(err)
	}
	return path
}

// The local daemon is a target like any other, so it has to be asked for. A
// machine with no outbound peers used to fall back to it, which is how a model
// ends up typing into the machine the operator is sitting at while they believe
// it is somewhere else. The local target is not subject to a pre-approval
// prompt, so nothing else would have said so.
func TestNoPeerAndNoOutboundPeerIsAnError(t *testing.T) {
	path := writePeers(t, &peers.File{Peers: []peers.Peer{{ID: "p1", Nickname: "laptop", Direction: "inbound"}}})
	_, err := mcpTargets(options{peers: path})
	if err == nil {
		t.Fatal("a machine with no outbound peer must not resolve to a target")
	}
	for _, want := range []string{"no outbound peers", "--peer", "local"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestPeerLocalIsThisMachinesDaemon(t *testing.T) {
	path := writePeers(t, &peers.File{})
	targets, err := mcpTargets(options{peers: path, peer: mcpLocalRef})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].label != mcpLocalRef || targets[0].peerID != "" {
		t.Fatalf("targets = %+v, want the local daemon", targets)
	}
}

func TestUnknownPeerSaysWhatToDoInstead(t *testing.T) {
	path := writePeers(t, &peers.File{})
	_, err := mcpTargets(options{peers: path, peer: "nas"})
	if err == nil {
		t.Fatal("an unknown peer must not resolve")
	}
	for _, want := range []string{"tyd peer list", "--peer local"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestAllowPeerRefusesTheLocalDaemonTwice(t *testing.T) {
	path := writePeers(t, &peers.File{})
	_, err := mcpTargets(options{peers: path, allowPeer: []string{mcpLocalRef, mcpLocalRef}})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("error = %v, want the local target refused twice", err)
	}
}

// One outbound peer and no --peer stays the default, so the common
// single-remote-machine setup needs no flag.
func TestTheOnlyOutboundPeerIsTheDefault(t *testing.T) {
	path := writePeers(t, &peers.File{Peers: []peers.Peer{{ID: "p1", Nickname: "laptop", Direction: "outbound"}}})
	targets, err := mcpTargets(options{peers: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].peerID != "p1" || targets[0].label != "laptop" {
		t.Fatalf("targets = %+v, want the only outbound peer", targets)
	}
}

func TestTargetLabelDoesNotRepeatTheSameName(t *testing.T) {
	if got := mcpTargetLabel(mcpTarget{label: "laptop", nickname: "laptop"}); got != "laptop" {
		t.Fatalf("label = %q", got)
	}
	if got := mcpTargetLabel(mcpTarget{label: "laptop", nickname: "osaka"}); got != "laptop (osaka)" {
		t.Fatalf("label = %q", got)
	}
	if got := mcpTargetLabel(mcpTarget{label: mcpLocalRef}); got != mcpLocalRef {
		t.Fatalf("label = %q, want the local target named", got)
	}
}

// `local` names this machine's daemon, so a peer may not answer to it. An
// operator who wrote --peer local was choosing this machine, and a peer
// stealing the name would send a model's commands elsewhere while the label
// still said local.
func TestALocalNicknameIsRefusedAtPairingTime(t *testing.T) {
	err := peers.ValidateNickname(mcpLocalRef)
	if err == nil {
		t.Fatal("a peer must not be able to take the reserved nickname")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("the error must say the name is reserved: %v", err)
	}
	// A nickname that merely contains it is fine.
	if err := peers.ValidateNickname("localhost-build"); err != nil {
		t.Fatalf("a nickname containing the reserved word is not the reserved word: %v", err)
	}
}

// The reserved word is resolved before any peer, so an older peers.json holding
// the name cannot take this machine's name away. The peer stays reachable by id
// and the error says so, because an operator can see that nickname in
// `tyd peer list` and would otherwise conclude the list was wrong.
func TestAPeerHoldingTheReservedNameDoesNotStealIt(t *testing.T) {
	path := writePeers(t, &peers.File{Peers: []peers.Peer{
		{ID: "0123456789abcdef", Nickname: mcpLocalRef, Direction: "outbound"},
	}})
	_, err := mcpTargets(options{peers: path, peer: mcpLocalRef})
	if err == nil {
		t.Fatal("a peer holding the reserved name must not answer for this machine")
	}
	for _, want := range []string{"own daemon", "0123456789abcdef", "peer alias"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must mention %q so the peer is still reachable: %v", want, err)
		}
	}
	// The same peer under its id resolves normally.
	targets, err := mcpTargets(options{peers: path, peer: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].peerID != "0123456789abcdef" {
		t.Fatalf("targets = %+v, want the peer by id", targets)
	}
}

// An empty --allow-peer is a target nobody can name. The space-separated form
// was already refused by the peer lookup; the = form reaches the same place, and
// the error should say what is wrong rather than that the name is unknown.
func TestAllowPeerRefusesAnEmptyName(t *testing.T) {
	path := writePeers(t, &peers.File{})
	_, err := mcpTargets(options{peers: path, allowPeer: []string{""}})
	if err == nil {
		t.Fatal("--allow-peer with an empty name must be refused")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("the error must say the name is empty: %v", err)
	}
}
