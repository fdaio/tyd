package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testBinder() []byte {
	b := make([]byte, BindingSize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestVerifyBindingAcceptsOwnSignature(t *testing.T) {
	pub, priv := testKey(t)
	binder := testBinder()
	if err := VerifyBinding(pub, nil, binder, SignBinding(priv, nil, binder)); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	// A nonce binds the signature to one handshake as well.
	nonce := []byte("nonce-1")
	if err := VerifyBinding(pub, nonce, binder, SignBinding(priv, nonce, binder)); err != nil {
		t.Fatalf("valid nonce-bound binding rejected: %v", err)
	}
}

// The whole point of the binding: a relay that re-terminates TLS derives a
// different exporter, so a signature lifted from another connection must not
// verify here.
func TestVerifyBindingRejectsAnotherSessionsBinder(t *testing.T) {
	pub, priv := testKey(t)
	other := make([]byte, BindingSize)
	copy(other, testBinder())
	other[0] ^= 0xff

	sig := SignBinding(priv, nil, other)
	if err := VerifyBinding(pub, nil, testBinder(), sig); err == nil {
		t.Fatal("binding from another TLS session verified")
	}
}

func TestVerifyBindingRejectsWrongKeyAndNonce(t *testing.T) {
	pub, priv := testKey(t)
	otherPub, _ := testKey(t)
	binder := testBinder()
	sig := SignBinding(priv, nil, binder)

	if err := VerifyBinding(otherPub, nil, binder, sig); err == nil {
		t.Error("another peer's key verified the binding")
	}
	if err := VerifyBinding(pub, []byte("nonce-1"), binder, sig); err == nil {
		t.Error("binding verified under a nonce it was not signed with")
	}
	if err := VerifyBinding(pub, nil, binder[:BindingSize-1], sig); err == nil {
		t.Error("short binding accepted")
	}
	if err := VerifyBinding(pub[:8], nil, binder, sig); err == nil {
		t.Error("short public key accepted")
	}
}

// A binding signature must not be replayable as an auth response, or the
// domain separation is decorative.
func TestBindingSignatureIsNotAnAuthSignature(t *testing.T) {
	pub, priv := testKey(t)
	nonce := []byte("challenge-nonce")
	binder := testBinder()

	bindingSig := SignBinding(priv, nonce, binder)
	if ed25519.Verify(pub, nonce, bindingSig) {
		t.Error("binding signature also verifies as a plain auth signature")
	}
	authSig := Sign(priv, nonce)
	if ed25519.Verify(pub, BindingPayload(nonce, binder), authSig) {
		t.Error("plain auth signature also verifies as a binding")
	}
}

func TestBindingPayloadIsUnambiguous(t *testing.T) {
	binder := testBinder()
	// Length-prefixing the nonce keeps (nonce, binder) from being reshuffled
	// into a different pair that hashes or signs the same.
	a := BindingPayload([]byte("ab"), []byte("c"))
	b := BindingPayload([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("nonce and binder are not separated in the signed payload")
	}
	if !bytes.Equal(BindingPayload([]byte("n"), binder), BindingPayload([]byte("n"), binder)) {
		t.Fatal("binding payload is not deterministic")
	}
}

// Without a binding the auth frame must stay byte-for-byte what it was, or
// every existing transport (unix, TLS, QUIC) breaks at once.
func TestAuthFrameWithoutBinderIsUnchanged(t *testing.T) {
	_, priv := testKey(t)
	nonce := []byte("n")
	bare := AuthFrame(priv, nonce)
	bound := AuthFrameBound(priv, nonce, nil)
	if bare.Type != bound.Type || !bytes.Equal(bare.Data, bound.Data) || !bytes.Equal(bare.PublicKey, bound.PublicKey) {
		t.Fatal("a nil binder changed the auth frame")
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), nonce, bare.Data) {
		t.Fatal("auth frame is not a plain signature over the nonce")
	}

	withBinder := AuthFrameBound(priv, nonce, testBinder())
	if bytes.Equal(withBinder.Data, bare.Data) {
		t.Fatal("binder did not change the signature")
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), BindingPayload(nonce, testBinder()), withBinder.Data) {
		t.Fatal("bound auth frame does not verify against the binding payload")
	}
}
