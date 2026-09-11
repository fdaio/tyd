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
	return protocol.Frame{
		Type:      protocol.TypeAuth,
		PublicKey: priv.Public().(ed25519.PublicKey),
		Data:      Sign(priv, nonce),
	}
}

func ChallengeFrame(nonce []byte) protocol.Frame {
	return protocol.Frame{Type: protocol.TypeChallenge, Data: nonce}
}

func Denied(cap Cap) error {
	return fmt.Errorf("permission denied: %s", cap)
}
