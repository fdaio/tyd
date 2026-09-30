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
	// The local target has no name, so it stays empty and reads as this machine.
	got = mcpPeerLabels([]mcpTarget{{label: ""}})
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("labels = %v, want the local target unnamed", got)
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
