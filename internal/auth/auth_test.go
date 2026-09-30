package auth

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndAuthenticate(t *testing.T) {
	priv, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := SignAuth(priv, nonce, nil)
	p, err := store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), sig)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "admin" {
		t.Fatalf("name %q", p.Name)
	}
	if !store.Allow(p, CapCreate, "") || !store.Allow(p, CapList, "") {
		t.Fatal("admin missing global caps")
	}
}

func TestRejectsUnknownKey(t *testing.T) {
	_, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	sig := SignAuth(other, nonce, nil)
	if _, err := store.Authenticate(nonce, other.Public().(ed25519.PublicKey), sig); err == nil {
		t.Fatal("expected untrusted key")
	}
}

func TestRejectsBadSignature(t *testing.T) {
	priv, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	sig := SignAuth(priv, nonce, nil)
	sig[0] ^= 0xff
	if _, err := store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), sig); err == nil {
		t.Fatal("expected bad signature")
	}
}

// A client from before the auth payload carried a label signed the bare nonce.
// That signature is the one a peer can carry from one daemon to another, so it
// must be refused, and the refusal has to name the cause.
func TestRejectsLegacyNonceSignature(t *testing.T) {
	priv, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	_, err = store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), Sign(priv, nonce))
	if err == nil {
		t.Fatal("bare-nonce signature accepted")
	}
	if !strings.Contains(err.Error(), "older tyd") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestAttachDoesNotImplyWrite(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	store.Add("reader", priv.Public().(ed25519.PublicKey), nil)
	if err := store.Grant(priv.Public().(ed25519.PublicKey), "sess-a", CapAttach); err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	p, err := store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), SignAuth(priv, nonce, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !store.Allow(p, CapAttach, "sess-a") {
		t.Fatal("expected attach")
	}
	if store.Allow(p, CapWrite, "sess-a") {
		t.Fatal("attach must not imply write")
	}
	if store.Allow(p, CapAttach, "sess-b") {
		t.Fatal("session A grant must not apply to B")
	}
	if store.Allow(p, CapClose, "sess-a") {
		t.Fatal("no close grant")
	}
}

func TestGrantOwnerCapsOnSession(t *testing.T) {
	priv, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := store.Grant(pub, "s1", OwnerCaps...); err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	p, err := store.Authenticate(nonce, pub, SignAuth(priv, nonce, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range OwnerCaps {
		if !store.Allow(p, c, "s1") {
			t.Fatalf("missing %s", c)
		}
		if store.Allow(p, c, "s2") {
			t.Fatalf("%s leaked to other session", c)
		}
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	if err := WriteIdentity(path, priv); err != nil {
		t.Fatal(err)
	}
	got, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if EncodePublic(got.Public().(ed25519.PublicKey)) != EncodePublic(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("public key mismatch")
	}
}

func TestTrustFileRoundTrip(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "trusted.json")
	if err := WriteBootstrapTrust(path, "dev", pub); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := NewNonce()
	p, err := store.Authenticate(nonce, pub, SignAuth(priv, nonce, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "dev" || !store.Allow(p, CapCreate, "") {
		t.Fatalf("loaded principal %+v", p)
	}
}

func TestEnsureIdentityCreatesOnce(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id_ed25519")
	trustPath := filepath.Join(dir, "trusted.json")
	key, created, err := EnsureIdentity(idPath, trustPath)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Fatal("bad key")
	}
	if _, err := os.Stat(trustPath); err != nil {
		t.Fatal(err)
	}
	again, created2, err := EnsureIdentity(idPath, trustPath)
	if err != nil || created2 {
		t.Fatalf("created2=%v err=%v", created2, err)
	}
	if EncodePublic(key.Public().(ed25519.PublicKey)) != EncodePublic(again.Public().(ed25519.PublicKey)) {
		t.Fatal("identity changed")
	}
}

func TestDropUnlistedPeers(t *testing.T) {
	store := NewStore()
	_, a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	store.Add("local", a.Public().(ed25519.PublicKey), AllGlobal)
	store.EnsurePeer("peer", b.Public().(ed25519.PublicKey), AllGlobal)
	store.DropUnlistedPeers(nil)
	nonce, _ := NewNonce()
	if _, err := store.Authenticate(nonce, b.Public().(ed25519.PublicKey), SignAuth(b, nonce, nil)); err == nil {
		t.Fatal("revoked peer still trusted")
	}
	if _, err := store.Authenticate(nonce, a.Public().(ed25519.PublicKey), SignAuth(a, nonce, nil)); err != nil {
		t.Fatalf("local principal dropped: %v", err)
	}
}
