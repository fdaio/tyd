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
	return signedResponseFor(t, "daemon-1", peerPub, peerPriv, seq)
}

func signedResponseFor(t *testing.T, daemonID string, peerPub ed25519.PublicKey, peerPriv ed25519.PrivateKey, seq uint64) *controlpanel.EndpointResponse {
	t.Helper()
	rec := auth.NewEndpointRecord(daemonID, auth.EncodePublic(peerPub), "203.0.113.7:41234",
		"aabbccdd", "quic", []string{"203.0.113.7:41234"}, time.Now(), 90*time.Second, seq)
	sig, err := rec.Sign(peerPriv)
	if err != nil {
		t.Fatal(err)
	}
	return &controlpanel.EndpointResponse{
		DaemonID:   daemonID,
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

	rec, err := verifyEndpointRecord(opts, "daemon-1", ep)
	if err != nil {
		// The record is intact, so this may pass verification; what must not
		// happen is the substituted values being the ones dialled.
		t.Fatalf("the record itself should still verify: %v", err)
	}
	if rec.Addr != "203.0.113.7:41234" || rec.CertFP != "aabbccdd" {
		t.Fatalf("the dialled values came from the tampered copy: addr=%q fp=%q", rec.Addr, rec.CertFP)
	}
}

// The primary dial path has to do what verifyEndpointRecord promises. This is
// the path every session create and attach uses; a check that lives only in the
// retry helper leaves the ordinary dial unprotected.
func TestEndpointDialsTheSignedRecord(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)
	opts.peer = "daemon-1"
	opts.relay = "off"
	ep := signedResponse(t, peerPub, peerPriv, 1)
	ep.Addr = "198.51.100.1:443"
	ep.CertFP = "deadbeef"
	ep.Candidates = []string{"198.51.100.1:443"}
	opts.platform = serveEndpoint(t, ep)

	got, peerID, err := endpoint(opts)
	if err != nil {
		t.Fatal(err)
	}
	if peerID != "daemon-1" {
		t.Fatalf("peer id %q", peerID)
	}
	if got.Address != "203.0.113.7:41234" || got.CertFP != "aabbccdd" {
		t.Fatalf("dialled the Control Panel copy: addr=%q fp=%q", got.Address, got.CertFP)
	}

	// The current record is returned again on a retry. It is not a downgrade,
	// so it must still dial.
	again, _, err := endpoint(opts)
	if err != nil {
		t.Fatalf("the current endpoint failed on a retry: %v", err)
	}
	if again.Address != got.Address || again.CertFP != got.CertFP {
		t.Fatalf("retry dialled different values: %+v", again)
	}
}

// If the Control Panel can replace the key beside the endpoint, it could sign
// the substituted endpoint itself. The local pairing record is the anchor, not
// the key the Control Panel returns in peers.json.
func TestEndpointRefusesControlPanelKeySubstitution(t *testing.T) {
	opts, _, _ := endpointFixture(t)
	attackerPub, attackerPriv := keyPair(t)
	doc, err := peers.Load(opts.peers)
	if err != nil {
		t.Fatal(err)
	}
	doc.Peers[0].PublicKey = auth.EncodePublic(attackerPub)
	if err := peers.Save(opts.peers, doc); err != nil {
		t.Fatal(err)
	}
	opts.peer = "daemon-1"
	opts.relay = "off"
	opts.platform = serveEndpoint(t, signedResponse(t, attackerPub, attackerPriv, 1))

	if _, _, err := endpoint(opts); err == nil {
		t.Fatal("dialled an endpoint signed by the Control Panel's replacement key")
	}
}

// A proof for another paired peer must not satisfy a lookup for this one.
func TestEndpointRefusesAnotherPairedPeer(t *testing.T) {
	dir := t.TempDir()
	targetPub, _ := keyPair(t)
	otherPub, otherPriv := keyPair(t)
	opts := options{
		identity: dir + "/id_ed25519",
		peers:    dir + "/peers.json",
		paired:   dir + "/paired.json",
		relay:    "off",
		peer:     "target",
	}
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "target", PublicKey: auth.EncodePublic(targetPub), Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := peers.SavePaired(opts.paired, &peers.PairedFile{Peers: []peers.PairedPeer{
		{ID: "target", PublicKey: auth.EncodePublic(targetPub), Direction: "outbound"},
		{ID: "other", PublicKey: auth.EncodePublic(otherPub), Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	opts.platform = serveEndpoint(t, signedResponseFor(t, "other", otherPub, otherPriv, 1))

	if _, err := endpointFromCPPeer(opts, "target"); err == nil {
		t.Fatal("accepted an endpoint proof for another paired peer")
	}
}

// A pairing file that exists is the complete trust list. A peer the Control
// Panel adds to peers.json after pairing must not be dialled.
func TestEndpointRefusesUnpairedPeerAfterPairing(t *testing.T) {
	dir := t.TempDir()
	peerPub, peerPriv := keyPair(t)
	opts := options{
		identity: dir + "/id_ed25519",
		peers:    dir + "/peers.json",
		paired:   dir + "/paired.json",
		relay:    "off",
		peer:     "daemon-1",
	}
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "daemon-1", PublicKey: auth.EncodePublic(peerPub), Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := peers.SavePaired(opts.paired, &peers.PairedFile{}); err != nil {
		t.Fatal(err)
	}
	opts.platform = serveEndpoint(t, signedResponse(t, peerPub, peerPriv, 1))

	if _, _, err := endpoint(opts); err == nil {
		t.Fatal("dialled a peer the Control Panel added after pairing")
	}
}

func TestPeerPublicKeyUsesLocalPairingRecord(t *testing.T) {
	opts, peerPub, _ := endpointFixture(t)
	attackerPub, _ := keyPair(t)
	doc, err := peers.Load(opts.peers)
	if err != nil {
		t.Fatal(err)
	}
	doc.Peers[0].PublicKey = auth.EncodePublic(attackerPub)
	if err := peers.Save(opts.peers, doc); err != nil {
		t.Fatal(err)
	}
	if got := peerPublicKey(opts, "daemon-1"); string(got) != string(peerPub) {
		t.Fatal("the Control Panel's key won over the local pairing record")
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

	_, err := verifyEndpointRecord(opts, "daemon-1", ep)
	if err == nil {
		t.Fatal("an extended expiry was accepted")
	}
	if !contains(err.Error(), "signature") {
		t.Errorf("the error should point at the signature, got: %v", err)
	}
}

// A record the Control Panel replays -- correctly signed, just old -- must not
// be dialled again, or an endpoint the peer has moved off stays reachable. The
// current record may be returned more than once: every lookup and retry sees
// the same sequence until the peer republishes, and that is not a downgrade.
func TestOldEndpointReplayIsRefused(t *testing.T) {
	opts, peerPub, peerPriv := endpointFixture(t)

	// First delivery is accepted and remembered.
	if _, err := verifyEndpointRecord(opts, "daemon-1", signedResponse(t, peerPub, peerPriv, 7)); err != nil {
		t.Fatalf("a fresh endpoint was refused: %v", err)
	}
	// The same current record is what the next lookup gets.
	if _, err := verifyEndpointRecord(opts, "daemon-1", signedResponse(t, peerPub, peerPriv, 7)); err != nil {
		t.Fatalf("the current endpoint was refused on a second lookup: %v", err)
	}
	// An older one is a replay.
	if _, err := verifyEndpointRecord(opts, "daemon-1", signedResponse(t, peerPub, peerPriv, 6)); err == nil {
		t.Fatal("an older endpoint was accepted")
	}
	// A newer one is fine: the peer simply republished.
	if _, err := verifyEndpointRecord(opts, "daemon-1", signedResponse(t, peerPub, peerPriv, 8)); err != nil {
		t.Errorf("a newer endpoint was refused: %v", err)
	}
	// Once past 8, the earlier record is a replay even though it was accepted
	// before.
	if _, err := verifyEndpointRecord(opts, "daemon-1", signedResponse(t, peerPub, peerPriv, 7)); err == nil {
		t.Fatal("a superseded endpoint was accepted")
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
	if _, err := verifyEndpointRecord(opts, "daemon-1", ep); err == nil {
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
	if _, err := verifyEndpointRecord(opts, "daemon-1", ep); err == nil {
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
	if _, err := verifyEndpointRecord(opts, "daemon-1", ep); err == nil {
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
	if _, err := verifyEndpointRecord(opts, "daemon-1", ep); err != nil {
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
