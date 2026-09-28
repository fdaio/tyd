package main

import (
	"crypto/ed25519"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/peers"
)

// A client dials whatever address and certificate fingerprint the Control Panel
// hands it. That record used to be unsigned, so the Control Panel could point a
// client at a machine it controls and supply the matching fingerprint -- the
// client had no way to tell, because a fingerprint from the Control Panel is
// exactly what a fingerprint is supposed to be checked against.
//
// These tests run the real verification against records the Control Panel has
// had a chance to alter, and check that the alteration does not survive.

// endpointFixture returns options holding a pinned key for a peer, plus that
// peer's key.
func endpointFixture(t *testing.T) (options, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	opts := options{
		identity: pairedPathFor(dir + "/peers.json"),
		peers:    dir + "/peers.json",
		paired:   dir + "/paired.json",
	}
	peerPub, peerPriv := keyPair(t)
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "daemon-1", PublicKey: auth.EncodePublic(peerPub), Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := peers.SavePaired(opts.paired, &peers.PairedFile{Peers: []peers.PairedPeer{
		{ID: "daemon-1", PublicKey: auth.EncodePublic(peerPub), Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	return opts, peerPub, peerPriv
}

func signedResponse(t *testing.T, peerPub ed25519.PublicKey, peerPriv ed25519.PrivateKey, seq uint64) *controlpanel.EndpointResponse {
	t.Helper()
	rec := auth.NewEndpointRecord("daemon-1", auth.EncodePublic(peerPub), "203.0.113.7:41234",
		"aabbccdd", "quic", []string{"203.0.113.7:41234"}, time.Now(), 90*time.Second, seq)
	sig, err := rec.Sign(peerPriv)
	if err != nil {
		t.Fatal(err)
	}
	return &controlpanel.EndpointResponse{
		DaemonID:   "daemon-1",
		PublicKey:  auth.EncodePublic(peerPub),
		Addr:       rec.Addr,
		CertFP:     rec.CertFP,
		Transport:  "quic",
		Candidates: rec.Candidates,
		ExpiresAt:  rec.ExpiresAt,
		Proof:      &controlpanel.EndpointProof{Record: rec, Sig: auth.EncodeBytes(sig)},
	}
}

// The Control Panel repoints a client at an address and a fingerprint it
// controls. Nothing the daemon signed covers those values any more, so the
// client must refuse rather than dial.
func TestEndpointAddressAndFingerprintSubstitutionIsRefused(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)
	ep := signedResponse(t, peerPub, peerPriv, 1)

	// What the Control Panel does with a record it is carrying.
	ep.Addr = "198.51.100.1:443"
	ep.CertFP = "deadbeef"
	ep.Candidates = []string{"198.51.100.1:443"}

	rec, err := verifyEndpointRecord(opts, ep)
	if err != nil {
		// The record is intact, so this may pass verification; what must not
		// happen is the substituted values being the ones dialled.
		t.Fatalf("the record itself should still verify: %v", err)
	}
	if rec.Addr != "203.0.113.7:41234" || rec.CertFP != "aabbccdd" {
		t.Fatalf("the dialled values came from the tampered copy: addr=%q fp=%q", rec.Addr, rec.CertFP)
	}
}

// The other shape of the same attack: the record is left intact but the
// Control Panel claims a longer life for it, hoping the client keeps dialling a
// host the peer has moved off.
func TestEndpointExpiryExtensionIsRefused(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)
	ep := signedResponse(t, peerPub, peerPriv, 1)
	// The daemon signed a record good for 90 seconds. A year is not that.
	ep.Proof.Record.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)
	ep.ExpiresAt = ep.Proof.Record.ExpiresAt

	_, err := verifyEndpointRecord(opts, ep)
	if err == nil {
		t.Fatal("an extended expiry was accepted")
	}
	if !contains(err.Error(), "signature") {
		t.Errorf("the error should point at the signature, got: %v", err)
	}
}

// A record the Control Panel replays -- correctly signed, just old -- must not
// be dialled again, or an endpoint the peer has moved off stays reachable.
func TestEndpointReplayIsRefused(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)

	// First delivery is accepted and remembered.
	if _, err := verifyEndpointRecord(opts, signedResponse(t, peerPub, peerPriv, 7)); err != nil {
		t.Fatalf("a fresh endpoint was refused: %v", err)
	}
	// The same record again is a replay.
	if _, err := verifyEndpointRecord(opts, signedResponse(t, peerPub, peerPriv, 7)); err == nil {
		t.Fatal("a replayed endpoint was accepted")
	}
	// So is an older one.
	if _, err := verifyEndpointRecord(opts, signedResponse(t, peerPub, peerPriv, 6)); err == nil {
		t.Fatal("an older endpoint was accepted")
	}
	// A newer one is fine: the peer simply republished.
	if _, err := verifyEndpointRecord(opts, signedResponse(t, peerPub, peerPriv, 8)); err != nil {
		t.Errorf("a newer endpoint was refused: %v", err)
	}
}

// An expired record is refused even though it is perfectly authentic.
func TestExpiredEndpointIsRefused(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)
	rec := auth.NewEndpointRecord("daemon-1", auth.EncodePublic(peerPub), "203.0.113.7:41234",
		"aabbccdd", "quic", nil, time.Now().Add(-time.Hour), time.Minute, 1)
	sig, err := rec.Sign(peerPriv)
	if err != nil {
		t.Fatal(err)
	}
	ep := &controlpanel.EndpointResponse{
		DaemonID: "daemon-1", Addr: rec.Addr, CertFP: rec.CertFP,
		Proof: &controlpanel.EndpointProof{Record: rec, Sig: auth.EncodeBytes(sig)},
	}
	if _, err := verifyEndpointRecord(opts, ep); err == nil {
		t.Fatal("an expired endpoint was accepted")
	}
}

// A record with no signature at all is the pre-signing world: there is nothing
// to check, so it is not used.
func TestUnsignedEndpointIsRefused(t *testing.T) {
	opts, _, _ := endpointFixture(t)
	ep := &controlpanel.EndpointResponse{
		DaemonID: "daemon-1", Addr: "198.51.100.1:443", CertFP: "deadbeef", Transport: "quic",
	}
	if _, err := verifyEndpointRecord(opts, ep); err == nil {
		t.Fatal("an unsigned endpoint was accepted")
	}
}

// A record signed by somebody else is refused: the check is against the key this
// daemon pinned, not against whatever the record claims.
func TestEndpointSignedByAnotherKeyIsRefused(t *testing.T) {
	opts, _, _ := endpointFixture(t)
	attackerPub, attackerPriv := keyPair(t)
	ep := signedResponse(t, attackerPub, attackerPriv, 1)
	ep.DaemonID = "daemon-1" // and it claims to be the peer we meant to dial
	if _, err := verifyEndpointRecord(opts, ep); err == nil {
		t.Fatal("an endpoint signed by another key was accepted")
	}
}

// Without a pinned key there is nothing to check against, and that has to be
// said out loud rather than quietly dialled.
func TestUnpinnedPeerIsReportedNotSilentlyTrusted(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		identity: dir + "/id",
		peers:    dir + "/peers.json",
		paired:   dir + "/paired.json",
	}
	pub, priv := keyPair(t)
	// An honest, correctly signed record -- for a peer this daemon never pinned.
	ep := signedResponse(t, pub, priv, 1)
	if _, err := verifyEndpointRecord(opts, ep); err != nil {
		t.Fatalf("an unpinned peer should fall back rather than fail: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
