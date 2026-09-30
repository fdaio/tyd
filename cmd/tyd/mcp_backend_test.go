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

// A peer that really is called "local" keeps its name: the peer lookup comes
// first, so the reserved word is only a fallback. It fails safe, because the
// target it picks is named in the startup line and in every result.
func TestAPeerNamedLocalIsNotTheLocalDaemon(t *testing.T) {
	path := writePeers(t, &peers.File{Peers: []peers.Peer{{ID: "p1", Nickname: mcpLocalRef, Direction: "outbound"}}})
	targets, err := mcpTargets(options{peers: path, peer: mcpLocalRef})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].peerID != "p1" {
		t.Fatalf("targets = %+v, want the paired peer named local", targets)
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
