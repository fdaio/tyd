package client

import (
	"crypto/ed25519"
	"net"
	"strings"
	"testing"

	"tyd/internal/protocol"
)

// The relay cannot be used unless this host can say which peer came out of it.
// When no key is pinned there is nothing to check, and when a key is pinned but
// the peer answers with another one the connection is refused. Those two need
// different words: the first is missing local state, the second is a refusal,
// and telling someone to pair again in either case sends them down the wrong
// path.

// A peer with no pinned key is a local gap, and the message says so and names
// the commands that close it.
func TestMissingPinnedKeyIsReportedAsLocalState(t *testing.T) {
	err := verifyRelayBinding(nil, Endpoint{PeerID: "daemon-1"}, nil)
	if err == nil {
		t.Fatal("a peer with no pinned key was accepted")
	}
	msg := err.Error()
	if strings.Contains(msg, "re-pair") {
		t.Errorf("the message tells the user to pair again without saying the key is missing: %q", msg)
	}
	if !strings.Contains(msg, "no key pinned") {
		t.Errorf("the message does not say what is missing: %q", msg)
	}
	if !strings.Contains(msg, "daemon-1") {
		t.Errorf("the message does not name the peer: %q", msg)
	}
	if !strings.Contains(msg, "tyd revoke") {
		t.Errorf("the message does not say how to recover: %q", msg)
	}
}

// The peer answered with a key that is not the pinned one. Pairing again would
// replace a correct key with whatever the peer sends next, so the message has to
// read as a refusal.
func TestPinnedKeyMismatchIsReportedAsRefused(t *testing.T) {
	pinned, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()

	go func() {
		_ = protocol.WriteFrame(srv, protocol.Frame{Type: protocol.TypeBound, PublicKey: other})
	}()

	err = verifyRelayBinding(cli, Endpoint{PeerID: "daemon-1", PeerPublic: pinned}, nil)
	if err == nil {
		t.Fatal("a peer presenting an unpinned key was accepted")
	}
	msg := err.Error()
	if strings.Contains(msg, "re-pair") || strings.Contains(msg, "tyd revoke") {
		t.Errorf("the message asks for a new pairing instead of reporting a refusal: %q", msg)
	}
	if !strings.Contains(msg, "refused") {
		t.Errorf("the message does not report a refusal: %q", msg)
	}
	if !strings.Contains(msg, "daemon-1") {
		t.Errorf("the message does not name the peer: %q", msg)
	}
}
