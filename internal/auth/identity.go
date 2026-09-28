package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"tyd/internal/safefile"
)

func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func WriteIdentity(path string, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := safefile.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return safefile.WriteFile(path+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

func LoadIdentity(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(trimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// EnsureIdentity loads an existing identity or creates one (and bootstrap trust if missing).
func EnsureIdentity(identityPath, trustPath string) (ed25519.PrivateKey, bool, error) {
	if key, err := LoadIdentity(identityPath); err == nil {
		return key, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	_, priv, err := Generate()
	if err != nil {
		return nil, false, err
	}
	if err := WriteIdentity(identityPath, priv); err != nil {
		return nil, false, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := os.Stat(trustPath); os.IsNotExist(err) {
		if err := WriteBootstrapTrust(trustPath, "local", pub); err != nil {
			return nil, false, err
		}
	}
	return priv, true, nil
}

func EncodePublic(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// EncodeBytes renders binary material for transport in a JSON field.
func EncodeBytes(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeBytes is the inverse of EncodeBytes.
func DecodeBytes(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(trimSpace(s))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func DecodePublic(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(trimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\n' || s[j-1] == '\r' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
