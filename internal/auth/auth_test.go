package auth

import (
	"crypto/ed25519"
	"path/filepath"
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
	sig := Sign(priv, nonce)
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
	sig := Sign(other, nonce)
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
	sig := Sign(priv, nonce)
	sig[0] ^= 0xff
	if _, err := store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), sig); err == nil {
		t.Fatal("expected bad signature")
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
	p, err := store.Authenticate(nonce, priv.Public().(ed25519.PublicKey), Sign(priv, nonce))
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
	p, err := store.Authenticate(nonce, pub, Sign(priv, nonce))
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
	p, err := store.Authenticate(nonce, pub, Sign(priv, nonce))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "dev" || !store.Allow(p, CapCreate, "") {
		t.Fatalf("loaded principal %+v", p)
	}
}
