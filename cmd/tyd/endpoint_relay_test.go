package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/peers"
)

// A peer behind NAT is dialled directly first, and when every candidate times
// out the client falls back to the relay using the same endpoint. That fallback
// checks the peer against the key pinned at pairing, so an endpoint leaving
// that key unset cannot complete a session. A direct dial covers the loss with
// a certificate fingerprint, which is why only a NAT-bound peer notices.
//
// These tests pin the key onto every endpoint endpoint() returns.

// startCP serves a Control Panel holding one registered daemon. The caller
// signs and publishes the endpoint afterwards, once it knows the daemon id the
// Control Panel assigned.
func startCP(t *testing.T, pub ed25519.PublicKey) (*controlpanel.Service, *httptest.Server, string) {
	t.Helper()
	svc := controlpanel.New()
	srv := httptest.NewServer(svc.Handler())
	t.Cleanup(srv.Close)
	reg, err := svc.Register(controlpanel.RegisterRequest{PublicKey: auth.EncodePublic(pub)})
	if err != nil {
		t.Fatal(err)
	}
	return svc, srv, reg.ID
}

// serveEndpoint answers the endpoint lookup with the given record, so a test can
// present a Control Panel answer the real service would refuse to publish.
func serveEndpoint(t *testing.T, resp *controlpanel.EndpointResponse) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// pinnedOpts writes a peers file pinning pub for one peer and returns options
// pointing at the given Control Panel, with the relay enabled.
func pinnedOpts(t *testing.T, platform, peerID string, pub ed25519.PublicKey) options {
	t.Helper()
	dir := t.TempDir()
	opts := options{
		identity: dir + "/id_ed25519",
		peers:    dir + "/peers.json",
		paired:   pairedPathFor(dir + "/peers.json"),
		recent:   dir + "/recent.json",
		platform: platform,
		peer:     peerID,
		relay:    "https://relay.example",
	}
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: peerID, PublicKey: auth.EncodePublic(pub), Nickname: "box", Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	return opts
}

// signEndpoint builds a daemon-signed endpoint record for the given candidates.
func signEndpoint(t *testing.T, daemonID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, addrs []string, seq uint64) *controlpanel.EndpointResponse {
	t.Helper()
	addr, fp := "", ""
	if len(addrs) > 0 {
		addr, fp = addrs[0], "aabbccdd"
	}
	rec := auth.NewEndpointRecord(daemonID, auth.EncodePublic(pub), addr, fp, "quic", addrs, time.Now(), 90*time.Second, seq)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	return &controlpanel.EndpointResponse{
		DaemonID:   daemonID,
		PublicKey:  auth.EncodePublic(pub),
		Addr:       rec.Addr,
		CertFP:     rec.CertFP,
		Transport:  "quic",
		Candidates: addrs,
		ExpiresAt:  rec.ExpiresAt,
		Proof:      &controlpanel.EndpointProof{Record: rec, Sig: auth.EncodeBytes(sig)},
	}
}

// The endpoint a direct dial uses also carries the relay, because the client
// falls back to it in place when the direct candidates are unreachable. The
// fallback then has to check the peer, so the key belongs on the endpoint the
// direct dial returns too.
func TestDirectEndpointCarriesPinnedKeyForTheRelayFallback(t *testing.T) {
	peerPub, peerPriv := keyPair(t)
	svc, srv, daemonID := startCP(t, peerPub)
	ep := signEndpoint(t, daemonID, peerPub, peerPriv, []string{"203.0.113.7:41234"}, 1)
	if _, err := svc.PublishEndpoint(daemonID, controlpanel.PublishEndpointRequest{
		PublicKey: auth.EncodePublic(peerPub),
		Addr:      ep.Addr,
		CertFP:    ep.CertFP,
		Transport: ep.Transport,
		Proof:     ep.Proof,
	}); err != nil {
		t.Fatal(err)
	}
	opts := pinnedOpts(t, srv.URL, daemonID, peerPub)

	got, peerID, err := endpoint(opts)
	if err != nil {
		t.Fatal(err)
	}
	if peerID != daemonID {
		t.Fatalf("peer id %q want %q", peerID, daemonID)
	}
	if got.Kind != "quic" {
		t.Fatalf("kind %q want quic, so the test is not on the direct path", got.Kind)
	}
	if len(got.RelayURLs) == 0 {
		t.Fatal("the direct endpoint has no relay to fall back to, so this test proves nothing")
	}
	if !bytes.Equal(got.PeerPublic, peerPub) {
		t.Fatal("the relay fallback on this endpoint has no pinned key to check the peer against")
	}
}

// A refreshed endpoint takes the same shape: a direct dial that may fall back
// to the relay, so it has to carry the key too.
func TestRefreshedEndpointCarriesPinnedKey(t *testing.T) {
	peerPub, peerPriv := keyPair(t)
	svc, srv, daemonID := startCP(t, peerPub)
	ep := signEndpoint(t, daemonID, peerPub, peerPriv, []string{"203.0.113.7:41234"}, 2)
	if _, err := svc.PublishEndpoint(daemonID, controlpanel.PublishEndpointRequest{
		PublicKey: auth.EncodePublic(peerPub),
		Addr:      ep.Addr,
		CertFP:    ep.CertFP,
		Transport: ep.Transport,
		Proof:     ep.Proof,
	}); err != nil {
		t.Fatal(err)
	}
	opts := pinnedOpts(t, srv.URL, daemonID, peerPub)

	got, err := endpointFromCPPeer(opts, daemonID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RelayURLs) == 0 {
		t.Fatal("the refreshed endpoint has no relay to fall back to, so this test proves nothing")
	}
	if !bytes.Equal(got.PeerPublic, peerPub) {
		t.Fatal("the refreshed endpoint has no pinned key for the relay fallback to check")
	}
}

// A peer that publishes no reachable endpoint is dialled through the relay.
// That endpoint is built without a dial address, so the pinned key is the only
// thing that identifies the peer.
func TestRelayFallbackEndpointCarriesPinnedKey(t *testing.T) {
	peerPub, _ := keyPair(t)
	_, srv, daemonID := startCP(t, peerPub)
	opts := pinnedOpts(t, srv.URL, daemonID, peerPub)

	// The daemon is known but holds no endpoint, which is the answer a client
	// gets for a peer that has not come up yet.
	got, peerID, err := endpoint(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "relay" {
		t.Fatalf("kind %q want relay", got.Kind)
	}
	if peerID != daemonID {
		t.Fatalf("peer id %q want %q", peerID, daemonID)
	}
	if !bytes.Equal(got.PeerPublic, peerPub) {
		t.Fatal("a relay-only endpoint has no pinned key, so the peer cannot be identified")
	}
}

// A published endpoint that offers no dial candidate sends the client to the
// relay on a path of its own, so that endpoint needs the key as well.
func TestNoCandidateEndpointCarriesPinnedKey(t *testing.T) {
	peerPub, peerPriv := keyPair(t)
	ep := signEndpoint(t, "daemon-1", peerPub, peerPriv, nil, 1)
	opts := pinnedOpts(t, serveEndpoint(t, ep), "daemon-1", peerPub)

	got, _, err := endpoint(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "relay" {
		t.Fatalf("kind %q want relay", got.Kind)
	}
	if !bytes.Equal(got.PeerPublic, peerPub) {
		t.Fatal("the no-candidate fallback has no pinned key")
	}
}

// A peer this daemon never pinned leaves nothing to check the relay peer
// against. That is a different problem from a key that fails to verify, and
// re-pairing a peer that is already pinned changes nothing, so the two have to
// be told apart.
func TestUnpinnedPeerHasNoPinnedKey(t *testing.T) {
	dir := t.TempDir()
	opts := options{peers: dir + "/peers.json"}
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "daemon-1", Direction: "outbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if got := peerPublicKey(opts, "daemon-1"); len(got) != 0 {
		t.Fatal("a peer stored without a key must not yield a pinned key")
	}
}
