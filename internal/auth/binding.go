package auth

import (
	"crypto/ed25519"
	"fmt"
)

// Channel binding ties an Ed25519 identity to one TLS session, so a relay that
// terminates TLS on one side and forwards to the other cannot pass the peer's
// signature off as valid: the two sessions derive different binding values.
//
// The relay path used to be a bare splice of the application protocol, which
// left the terminal stream in cleartext for the relay and for Cloudflare in
// front of it, and left nothing stopping injected bytes. The relay now carries
// an inner TLS session; these helpers are what make that session belong to a
// known peer rather than to whoever is in the middle.

// BindingLabel is the exporter label both sides use. It is part of the
// protocol: changing it invalidates every in-flight relay session.
const BindingLabel = "tyd relay e2e channel binding v1"

// BindingSize is the exported binding value length. 32 bytes matches the
// Ed25519 signature width and is what the exporter is asked for.
const BindingSize = 32

// bindingDomain separates the binding signature from any other signature this
// key produces, so a binding signature can never be replayed as an auth
// response or the other way round.
var bindingDomain = []byte("tyd-bind-v1\x00")

// BindingPayload is the exact byte string both peers sign: the domain, the
// nonce (empty when there is none), and the binding value. Exported so the
// client can verify a server binding without duplicating the layout.
func BindingPayload(nonce, binder []byte) []byte {
	out := make([]byte, 0, len(bindingDomain)+len(nonce)+len(binder)+2)
	out = append(out, bindingDomain...)
	out = append(out, byte(len(nonce)>>8), byte(len(nonce)))
	out = append(out, nonce...)
	out = append(out, binder...)
	return out
}

// SignBinding signs the binding payload with an identity key.
func SignBinding(priv ed25519.PrivateKey, nonce, binder []byte) []byte {
	if len(priv) != ed25519.PrivateKeySize {
		return nil
	}
	return Sign(priv, BindingPayload(nonce, binder))
}

// VerifyBinding checks a binding signature against an already-pinned peer
// public key. It deliberately does not consult the trust store: the caller
// knows which peer it dialled, and a store lookup would allow any trusted peer
// to stand in for the one on the other end of this connection.
func VerifyBinding(pub ed25519.PublicKey, nonce, binder, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid peer public key")
	}
	if len(binder) != BindingSize {
		return fmt.Errorf("invalid channel binding")
	}
	if !ed25519.Verify(pub, BindingPayload(nonce, binder), sig) {
		return fmt.Errorf("channel binding does not match this connection")
	}
	return nil
}
