package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/peers"
)

// The Control Panel is the party tyd does not trust. These tests run the real
// pairing and trust code against a Control Panel that lies, and check that the
// lie does not become trust.
//
// The rule under test: the Control Panel may withdraw trust, never grant it.

// hostileCP answers /v1/accept with an inviter key of its own choosing, which is
// what a Control Panel that wants to sit in the middle would do.
type hostileCP struct {
	srv         *httptest.Server
	swapInviter bool
	attackerKey ed25519.PublicKey
}

func startHostileCP(t *testing.T, swap bool) *hostileCP {
	t.Helper()
	h := &hostileCP{swapInviter: swap}
	real := controlpanel.New().Handler()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.swapInviter && strings.HasSuffix(r.URL.Path, "/v1/accept") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"self_id":"c","self_public_key":"","peer_id":"evil",` +
				`"peer_public_key":"` + auth.EncodePublic(h.attackerKey) + `"}`))
			return
		}
		real.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// Risk 1: the Control Panel substitutes the inviter's public key during accept.
// The token the operator carried names the real key, so the swap is caught and
// no pairing is recorded.
func TestAcceptRejectsSubstitutedInviterKey(t *testing.T) {
	dir := t.TempDir()
	clientDir := filepath.Join(dir, "client")
	if err := os.MkdirAll(clientDir, 0o700); err != nil {
		t.Fatal(err)
	}

	inviterPub, inviterPriv := keyPair(t)
	attackerPub, _ := keyPair(t)

	// A token minted the way `tyd invite` mints one, for a daemon id the
	// substituted Control Panel never heard of. That does not matter: the
	// accept response is intercepted before any lookup happens.
	token, err := auth.FormatInviteToken("inv-1", mustSecret(t), inviterPub)
	if err != nil {
		t.Fatal(err)
	}
	_ = inviterPriv

	hostile := startHostileCP(t, true)
	hostile.attackerKey = attackerPub

	err = run(options{
		identity: filepath.Join(clientDir, "id_ed25519"),
		trust:    filepath.Join(clientDir, "trusted.json"),
		peers:    filepath.Join(clientDir, "peers.json"),
		paired:   filepath.Join(clientDir, "paired.json"),
		platform: hostile.srv.URL,
		as:       "box",
		cmd:      "accept",
		rest:     []string{token.String()},
	})
	if err == nil {
		t.Fatal("accept succeeded against a Control Panel that substituted the inviter key")
	}
	if !strings.Contains(err.Error(), "does not match the invite token") {
		t.Errorf("the error should name the substitution, got: %v", err)
	}

	pf, err := peers.LoadPaired(filepath.Join(clientDir, "paired.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pf.Peers) != 0 {
		t.Errorf("a pairing was recorded despite the mismatch: %+v", pf.Peers)
	}
}

// Risk 2: the Control Panel lists a peer of its own on a daemon that is already
// paired. The peer carries no record this host can check, so it gains nothing,
// however often the sync repeats. A peer the Control Panel drops still loses
// trust, which is the only direction it is allowed to move things in.
func TestControlPanelCannotAddAPeerToTheTrustSet(t *testing.T) {
	opts, honestPub, injectedPub := trustFixture(t)

	doc := &peers.File{Peers: []peers.Peer{
		{ID: "honest", PublicKey: auth.EncodePublic(honestPub), Direction: "inbound"},
		{ID: "injected", PublicKey: auth.EncodePublic(injectedPub), Direction: "inbound"},
	}}

	store := auth.NewStore()
	injectPeerTrust(opts, store, doc)

	if !trustedByKey(store, honestPub) {
		t.Error("the honestly paired peer is not trusted")
	}
	if trustedByKey(store, injectedPub) {
		t.Error("a peer the Control Panel invented is trusted")
	}

	// A repeated sync is the same story: trust is not cumulative from upstream.
	injectPeerTrust(opts, store, doc)
	if trustedByKey(store, injectedPub) {
		t.Error("a repeated sync let the Control Panel add a peer")
	}

	// Revocation still works, because that only removes access: dropping the
	// honest peer from the Control Panel's list has to take its trust away.
	doc.Peers = doc.Peers[1:]
	injectPeerTrust(opts, store, doc)
	if trustedByKey(store, honestPub) {
		t.Error("a revoked peer is still trusted")
	}
}

// A record that does not verify is not a weaker case, it is a broken one. It
// must not be trusted, even though a legacy peer sitting next to it is.
func TestUnverifiableRecordIsNotTrustedButLegacyIs(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		peers:    filepath.Join(dir, "peers.json"),
		paired:   filepath.Join(dir, "paired.json"),
	}
	secret := mustSecret(t)

	// Signed by the acceptor but never countersigned: the shape a Control Panel
	// could assemble if it held the acceptor's key.
	halfPub, halfPriv := keyPair(t)
	half := auth.NewPairingProof("inv-1", mustPub(t), halfPub)
	if err := half.SignAcceptor(halfPriv, secret); err != nil {
		t.Fatal(err)
	}
	legacyPub, _ := keyPair(t)

	if err := peers.SavePaired(opts.paired, &peers.PairedFile{Peers: []peers.PairedPeer{
		{ID: "half", PublicKey: auth.EncodePublic(halfPub), Proof: half},
		{ID: "legacy", PublicKey: auth.EncodePublic(legacyPub), Proof: &auth.PairingProof{Legacy: true}},
	}}); err != nil {
		t.Fatal(err)
	}

	store := auth.NewStore()
	injectPeerTrust(opts, store, &peers.File{Peers: []peers.Peer{
		{ID: "half", PublicKey: auth.EncodePublic(halfPub), Direction: "inbound"},
		{ID: "legacy", PublicKey: auth.EncodePublic(legacyPub), Direction: "inbound"},
	}})

	if trustedByKey(store, halfPub) {
		t.Error("a record with no inviter signature was trusted")
	}
	if !trustedByKey(store, legacyPub) {
		t.Error("a legacy peer should stay trusted so an upgrade does not cut anyone off")
	}
}

// A damaged or missing pairing record must not fall back to the Control Panel's
// view. That fallback is the mistake this change exists to remove.
func TestMissingPairingRecordTrustsNobody(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		peers:    filepath.Join(dir, "peers.json"),
		paired:   filepath.Join(dir, "paired.json"),
	}
	if err := os.WriteFile(opts.paired, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ := keyPair(t)
	store := auth.NewStore()
	injectPeerTrust(opts, store, &peers.File{Peers: []peers.Peer{
		{ID: "x", PublicKey: auth.EncodePublic(pub), Direction: "inbound"},
	}})
	if trustedByKey(store, pub) {
		t.Error("trust came from the Control Panel after the pairing record was lost")
	}
}

// An upgrade adopts the peers a daemon already had, once, so nobody is cut off.
// After that the record is the only source of trust.
func TestSeedPairedAdoptsExistingPeersOnce(t *testing.T) {
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		peers:    filepath.Join(dir, "peers.json"),
		paired:   filepath.Join(dir, "paired.json"),
	}
	oldPub, _ := keyPair(t)
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "old", PublicKey: auth.EncodePublic(oldPub), Direction: "inbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := seedPaired(opts); err != nil {
		t.Fatal(err)
	}
	pf, err := peers.LoadPaired(opts.paired)
	if err != nil {
		t.Fatal(err)
	}
	if len(pf.Peers) != 1 || !pf.Peers[0].Legacy() {
		t.Fatalf("existing peers were not adopted as legacy: %+v", pf.Peers)
	}

	// A peer that appears in peers.json later is not adopted: seeding runs once.
	if err := peers.Save(opts.peers, &peers.File{Peers: []peers.Peer{
		{ID: "old", PublicKey: auth.EncodePublic(oldPub), Direction: "inbound"},
		{ID: "new", PublicKey: auth.EncodePublic(mustPub(t)), Direction: "inbound"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := seedPaired(opts); err != nil {
		t.Fatal(err)
	}
	pf, err = peers.LoadPaired(opts.paired)
	if err != nil {
		t.Fatal(err)
	}
	if len(pf.Peers) != 1 {
		t.Errorf("seeding adopted a peer added after the upgrade: %+v", pf.Peers)
	}
}

// trustFixture sets up one honestly paired peer and returns the key of a peer
// the Control Panel would like to add.
func trustFixture(t *testing.T) (options, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		peers:    filepath.Join(dir, "peers.json"),
		paired:   filepath.Join(dir, "paired.json"),
	}
	honestPub, honestPriv := keyPair(t)
	inviterPub, inviterPriv := keyPair(t)

	proof := auth.NewPairingProof("inv-1", inviterPub, honestPub)
	if err := proof.SignAcceptor(honestPriv, mustSecret(t)); err != nil {
		t.Fatal(err)
	}
	if err := proof.Countersign(inviterPriv); err != nil {
		t.Fatal(err)
	}
	if !proof.Verified() {
		t.Fatal("fixture record does not verify")
	}
	if err := peers.SavePaired(opts.paired, &peers.PairedFile{Peers: []peers.PairedPeer{
		{ID: "honest", PublicKey: auth.EncodePublic(honestPub), Direction: "inbound", Proof: proof},
	}}); err != nil {
		t.Fatal(err)
	}
	injectedPub, _ := keyPair(t)
	return opts, honestPub, injectedPub
}

// trustedByKey reports whether the store would authenticate this key. The
// store only answers for keys it holds, so a miss means "not trusted".
func trustedByKey(store *auth.Store, pub ed25519.PublicKey) bool {
	return store.Has(auth.EncodePublic(pub))
}

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := keyPair(t)
	return pub
}

func mustSecret(t *testing.T) []byte {
	t.Helper()
	s, err := auth.NewInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var _ = cpclient.New
var _ = controlpanel.New
