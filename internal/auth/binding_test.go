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

	if ed25519.Verify(pub, AuthPayload(nonce, binder), SignBinding(priv, nonce, binder)) {
		t.Error("binding signature also verifies as an auth signature")
	}
	if ed25519.Verify(pub, BindingPayload(nonce, binder), SignAuth(priv, nonce, binder)) {
		t.Error("auth signature also verifies as a binding")
	}
}

func TestBindingPayloadIsUnambiguous(t *testing.T) {
	binder := testBinder()
	// Length-prefixing the nonce keeps (nonce, binder) from being reshuffled
	// into a different pair that signs the same.
	if bytes.Equal(BindingPayload([]byte("ab"), []byte("c")), BindingPayload([]byte("a"), []byte("bc"))) {
		t.Fatal("nonce and binder are not separated in the signed payload")
	}
	if !bytes.Equal(BindingPayload([]byte("n"), binder), BindingPayload([]byte("n"), binder)) {
		t.Fatal("binding payload is not deterministic")
	}
}

func TestAuthPayloadIsUnambiguous(t *testing.T) {
	binder := testBinder()
	// Length-prefixing the nonce keeps (nonce, binding) from being reshuffled
	// into a different pair that signs the same.
	if bytes.Equal(AuthPayload([]byte("ab"), []byte("c")), AuthPayload([]byte("a"), []byte("bc"))) {
		t.Fatal("nonce and binding are not separated in the signed payload")
	}
	if !bytes.Equal(AuthPayload([]byte("n"), binder), AuthPayload([]byte("n"), binder)) {
		t.Fatal("auth payload is not deterministic")
	}
}

// Every path signs the same shape: a domain label, the nonce, and the channel
// binding. The binding is empty only where there is no TLS session, and the
// signature is never a bare one over the nonce.
func TestAuthFrameCoversLabelNonceAndBinding(t *testing.T) {
	pub, priv := testKey(t)
	nonce := []byte("n")
	binder := testBinder()

	bare := AuthFrame(priv, nonce)
	bound := AuthFrameBound(priv, nonce, nil)
	if bare.Type != bound.Type || !bytes.Equal(bare.Data, bound.Data) || !bytes.Equal(bare.PublicKey, bound.PublicKey) {
		t.Fatal("AuthFrame and AuthFrameBound disagree without a binding")
	}
	if !ed25519.Verify(pub, AuthPayload(nonce, nil), bare.Data) {
		t.Fatal("auth frame does not verify against the auth payload")
	}
	if ed25519.Verify(pub, nonce, bare.Data) {
		t.Fatal("auth frame is a bare signature over the nonce")
	}

	withBinding := AuthFrameBound(priv, nonce, binder)
	if bytes.Equal(withBinding.Data, bare.Data) {
		t.Fatal("binding did not change the signature")
	}
	if !ed25519.Verify(pub, AuthPayload(nonce, binder), withBinding.Data) {
		t.Fatal("bound auth frame does not verify against the auth payload")
	}
}

// A signature made for one TLS session must not authenticate another one, or a
// peer can take it from the connection it was made on to a different daemon.
func TestAuthSignatureIsBoundToItsSession(t *testing.T) {
	priv, store, err := NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	session := testBinder()
	elsewhere := make([]byte, BindingSize)
	copy(elsewhere, session)
	elsewhere[0] ^= 0xff
	sig := SignAuth(priv, nonce, session)

	if _, err := store.AuthenticateBound(nonce, session, pub, sig); err != nil {
		t.Fatalf("valid session-bound auth rejected: %v", err)
	}
	if _, err := store.AuthenticateBound(nonce, elsewhere, pub, sig); err == nil {
		t.Fatal("auth from another session authenticated")
	}
	if _, err := store.AuthenticateBound(nonce, nil, pub, sig); err == nil {
		t.Fatal("auth accepted without the binding it was made under")
	}
}
