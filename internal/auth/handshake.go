package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"tyd/internal/protocol"
)

const nonceSize = 32

func NewNonce() ([]byte, error) {
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

func Sign(priv ed25519.PrivateKey, nonce []byte) []byte {
	return ed25519.Sign(priv, nonce)
}

func AuthFrame(priv ed25519.PrivateKey, nonce []byte) protocol.Frame {
	return AuthFrameBound(priv, nonce, nil)
}

// AuthFrameBound is AuthFrame with the signature also covering a channel
// binding. Over a plain transport the binding is nil, which keeps the signed
// bytes byte-for-byte what they were before. Over the relay it is the inner
// TLS exporter, so the server can tell that this auth belongs to this
// connection rather than to one a relay is splicing in from elsewhere.
func AuthFrameBound(priv ed25519.PrivateKey, nonce, binder []byte) protocol.Frame {
	data := Sign(priv, nonce)
	if len(binder) > 0 {
		data = SignBinding(priv, nonce, binder)
	}
	return protocol.Frame{
		Type:      protocol.TypeAuth,
		PublicKey: priv.Public().(ed25519.PublicKey),
		Data:      data,
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
	return protocol.Frame{Type: protocol.TypeChallenge, Data: nonce}
}

func Denied(cap Cap) error {
	return fmt.Errorf("permission denied: %s", cap)
}
