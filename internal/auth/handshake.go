package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"tyd/internal/protocol"
)

// NonceSize is the length of the challenge a daemon sends. The client refuses
// to sign a challenge of any other length, so a peer cannot turn this key into
// a signing oracle for messages of its own choosing.
const NonceSize = 32

// CurrentVersion is the handshake protocol version this build speaks. The
// accepted range is 1 to CurrentVersion: a peer that sends no version is older
// than every version here, and one that sends more is a build whose next
// incompatible change this code has never seen.
//
// The version travels outside the signature, so a peer can be told it is too old
// before anything is verified. Raising this constant is how the next
// incompatible change ships: every build that reads it refuses everything
// outside the range, and says which side to upgrade.
const CurrentVersion = 1

// MinHandshakeVersion is the oldest peer this build accepts. Raising it is how a
// later incompatible change ships; until then it is 1, which every version this
// code has spoken satisfies.
const MinHandshakeVersion = 1

// CheckVersion reports whether a peer speaking handshake version peerVersion
// can be talked to. peer names the role that version arrived from and self names
// the role this build is playing, so the message can say which program to
// upgrade.
//
// Both versions are in the message, because "handshake failed" is what this
// exists to replace: an old peer and an impostor produce the same failed
// signature otherwise, and only one of them is fixed by an upgrade.
func CheckVersion(self, peer string, peerVersion int) error {
	switch {
	case peerVersion <= 0:
		return fmt.Errorf("%s sends no handshake version, so it is older than version %d: upgrade the %s",
			peer, CurrentVersion, peer)
	case peerVersion > CurrentVersion:
		return fmt.Errorf("%s speaks handshake version %d, this %s speaks version %d: upgrade the %s",
			peer, peerVersion, self, CurrentVersion, peer)
	}
	return nil
}

func NewNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

func Sign(priv ed25519.PrivateKey, nonce []byte) []byte {
	return ed25519.Sign(priv, nonce)
}

// authDomain separates the login signature from the channel binding signature
// the same key makes on the relay, so neither can be replayed as the other.
var authDomain = []byte("tyd-auth-v1\x00")

// AuthPayload is the exact byte string both ends sign when authenticating: the
// domain, the nonce the daemon challenged with, and the channel binding of this
// connection. The binding is the TLS exporter wherever a TLS session exists,
// which no other session derives, so a signature made on one connection does
// not verify on another and cannot be handed to a third peer instead. It is
// empty on the unix socket, which has no TLS session to bind to.
func AuthPayload(nonce, binder []byte) []byte {
	out := make([]byte, 0, len(authDomain)+len(nonce)+len(binder)+2)
	out = append(out, authDomain...)
	out = append(out, byte(len(nonce)>>8), byte(len(nonce)))
	out = append(out, nonce...)
	out = append(out, binder...)
	return out
}

// SignAuth signs the auth payload. A key of the wrong size signs nothing; the
// caller reports that as an invalid identity.
func SignAuth(priv ed25519.PrivateKey, nonce, binder []byte) []byte {
	if len(priv) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.Sign(priv, AuthPayload(nonce, binder))
}

func AuthFrame(priv ed25519.PrivateKey, nonce []byte) protocol.Frame {
	return AuthFrameBound(priv, nonce, nil)
}

// AuthFrameBound is AuthFrame with the channel binding of this connection
// folded into the signed bytes, so the daemon can tell that the response
// belongs to the connection it arrived on rather than to one spliced in from
// elsewhere.
func AuthFrameBound(priv ed25519.PrivateKey, nonce, binder []byte) protocol.Frame {
	return protocol.Frame{
		Type:      protocol.TypeAuth,
		Version:   CurrentVersion,
		PublicKey: priv.Public().(ed25519.PublicKey),
		Data:      SignAuth(priv, nonce, binder),
	}
}

// BoundFrame is the server half of the relay channel binding: its identity
// signature over the TLS exporter, so the client learns it is talking to the
// peer it paired with and not to a relay that re-terminated TLS. The exporter
// is unique per session, so no nonce is needed to keep it fresh.
func BoundFrame(priv ed25519.PrivateKey, nonce, binder []byte) protocol.Frame {
	return protocol.Frame{
		Type:      protocol.TypeBound,
		PublicKey: priv.Public().(ed25519.PublicKey),
		Data:      SignBinding(priv, nonce, binder),
	}
}

func ChallengeFrame(nonce []byte) protocol.Frame {
	return protocol.Frame{Type: protocol.TypeChallenge, Version: CurrentVersion, Data: nonce}
}

func Denied(cap Cap) error {
	return fmt.Errorf("permission denied: %s", cap)
}
