package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Pairing trust.
//
// Everything a daemon needs to decide "may I trust this peer" used to come from
// the Control Panel: the inviter's public key at accept time, and the peer list
// on every sync. That makes the CP able to introduce a key it holds, and a
// daemon that trusts such a key hands over a session to it -- no protocol
// attack needed, the connection is perfectly well formed.
//
// The rule this file implements is the inverse: the Control Panel may withdraw
// trust, never grant it. A peer is trusted only when this daemon holds a
// pairing record it can verify itself.
//
// The record is anchored to an invite secret that the CP never sees. The
// inviter mints the secret locally, prints it beside the CP's invite id, and
// the person pairing the two machines moves that half across by hand. The CP
// sees an id it can expire and revoke, and nothing that lets it impersonate
// either side.

// PairingProofVersion is the record format. Bump it when the signed payload
// changes, so an old record cannot be read as a new one.
const PairingProofVersion = 1

// InviteSecretBytes is the length of the half the CP never sees.
const InviteSecretBytes = 32

// TokenHashBytes is how much of the inviter key digest rides in the token. It
// only has to be long enough that a substituted key does not collide by
// accident; it is not a security parameter on its own, because the secret and
// the signatures are.
const TokenHashBytes = 16

// PairingProof is the mutual record of one pairing. Either side can verify the
// half it is responsible for, and a third party -- the Control Panel
// included -- can neither add to it nor take anything from it.
type PairingProof struct {
	Version     int               `json:"version"`
	InviteID    string            `json:"invite_id"`
	Inviter     ed25519.PublicKey `json:"inviter"`
	Acceptor    ed25519.PublicKey `json:"acceptor"`
	AcceptorSig []byte            `json:"acceptor_sig,omitempty"`
	AcceptorMAC []byte            `json:"acceptor_mac,omitempty"`
	InviterSig  []byte            `json:"inviter_sig,omitempty"`
	PairedAt    time.Time         `json:"paired_at"`
	// Legacy marks a peer paired before records existed. Such a peer is still
	// trusted -- refusing would cut every existing installation off -- but its
	// trust still rests on the Control Panel, and tyd says so.
	Legacy bool `json:"legacy,omitempty"`
}

// PairingPayload is the exact bytes both sides sign. Length-prefixing keeps the
// three fields from being shuffled into a different triple that signs the same.
func PairingPayload(inviteID string, inviter, acceptor ed25519.PublicKey) []byte {
	out := make([]byte, 0, 3+len(inviteID)+2*ed25519.PublicKeySize)
	out = append(out, byte(PairingProofVersion))
	out = append(out, byte(len(inviteID)>>8), byte(len(inviteID)))
	out = append(out, inviteID...)
	out = append(out, inviter...)
	out = append(out, acceptor...)
	return out
}

// NewInviteSecret returns the half of the token the Control Panel never sees.
func NewInviteSecret() ([]byte, error) {
	s := make([]byte, InviteSecretBytes)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// TokenHash is the digest of the inviter's public key that rides in the token.
// The acceptor compares it against the key the Control Panel hands it, which is
// what stops the CP from substituting its own.
func TokenHash(inviter ed25519.PublicKey) []byte {
	sum := sha256.Sum256(inviter)
	return sum[:TokenHashBytes]
}

// InviteToken is a parsed pairing token.
type InviteToken struct {
	InviteID string
	Secret   []byte
	Hash     []byte
}

// String is the form the operator copies to the other machine.
func (t InviteToken) String() string {
	return t.InviteID + "." + hex.EncodeToString(t.Secret) + "." + hex.EncodeToString(t.Hash)
}

// FormatInviteToken builds the token an inviter prints. The inviter's own key is
// hashed in, so the acceptor can tell the CP's answer from the truth.
func FormatInviteToken(inviteID string, secret []byte, inviter ed25519.PublicKey) (InviteToken, error) {
	if strings.TrimSpace(inviteID) == "" {
		return InviteToken{}, fmt.Errorf("empty invite id")
	}
	if len(secret) != InviteSecretBytes {
		return InviteToken{}, fmt.Errorf("invite secret must be %d bytes, got %d", InviteSecretBytes, len(secret))
	}
	return InviteToken{InviteID: inviteID, Secret: secret, Hash: TokenHash(inviter)}, nil
}

// ParseInviteToken splits what the operator typed. A token without the secret
// half is a legacy CP-generated token and is reported as such, so the caller
// can decide what to do instead of silently accepting a weaker pairing.
func ParseInviteToken(token string) (InviteToken, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return InviteToken{}, fmt.Errorf("token must be <invite-id>.<secret>.<hash>")
	}
	secret, err := hex.DecodeString(parts[1])
	if err != nil {
		return InviteToken{}, fmt.Errorf("token secret is not hex: %w", err)
	}
	if len(secret) != InviteSecretBytes {
		return InviteToken{}, fmt.Errorf("token secret must be %d bytes, got %d", InviteSecretBytes, len(secret))
	}
	hash, err := hex.DecodeString(parts[2])
	if err != nil {
		return InviteToken{}, fmt.Errorf("token hash is not hex: %w", err)
	}
	if len(hash) != TokenHashBytes {
		return InviteToken{}, fmt.Errorf("token hash must be %d bytes, got %d", TokenHashBytes, len(hash))
	}
	return InviteToken{InviteID: parts[0], Secret: secret, Hash: hash}, nil
}

// MatchesInviter reports whether the key the Control Panel supplied is the one
// the inviter put in the token. This is the whole defence against a CP that
// swaps the inviter's public key during accept.
func (t InviteToken) MatchesInviter(inviter ed25519.PublicKey) bool {
	return hmac.Equal(t.Hash, TokenHash(inviter))
}

// NewPairingProof starts a record. The acceptor calls SignAcceptor; the inviter
// later adds its own signature with Countersign.
func NewPairingProof(inviteID string, inviter, acceptor ed25519.PublicKey) *PairingProof {
	return &PairingProof{
		Version:  PairingProofVersion,
		InviteID: inviteID,
		Inviter:  append(ed25519.PublicKey(nil), inviter...),
		Acceptor: append(ed25519.PublicKey(nil), acceptor...),
		PairedAt: time.Now().UTC(),
	}
}

// SignAcceptor fills in the acceptor's half: a signature over the pairing
// payload, plus an HMAC over its own public key keyed by the invite secret.
// The signature proves the acceptor holds its key; the MAC proves the acceptor
// actually saw the secret, which the Control Panel never had and therefore
// cannot forge on its behalf.
func (p *PairingProof) SignAcceptor(priv ed25519.PrivateKey, secret []byte) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid identity")
	}
	if len(secret) != InviteSecretBytes {
		return fmt.Errorf("invalid invite secret")
	}
	if !pubKeyOf(priv).Equal(p.Acceptor) {
		return fmt.Errorf("acceptor key does not match the private key")
	}
	p.AcceptorSig = Sign(priv, p.payload())
	mac := hmac.New(sha256.New, secret)
	mac.Write(p.Acceptor)
	p.AcceptorMAC = mac.Sum(nil)
	return nil
}

// VerifyAcceptor checks the acceptor's half. The inviter calls it with the
// secret it minted, so a record assembled by the Control Panel alone fails.
func (p *PairingProof) VerifyAcceptor(secret []byte) error {
	if p.Version != PairingProofVersion {
		return fmt.Errorf("unsupported pairing record version %d", p.Version)
	}
	if len(p.Acceptor) != ed25519.PublicKeySize {
		return fmt.Errorf("pairing record has no acceptor key")
	}
	if len(secret) != InviteSecretBytes {
		return fmt.Errorf("invalid invite secret")
	}
	if len(p.AcceptorSig) != ed25519.SignatureSize {
		return fmt.Errorf("pairing record has no acceptor signature")
	}
	if !ed25519.Verify(p.Acceptor, p.payload(), p.AcceptorSig) {
		return fmt.Errorf("acceptor signature does not match the pairing")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(p.Acceptor)
	if !hmac.Equal(p.AcceptorMAC, mac.Sum(nil)) {
		return fmt.Errorf("pairing record does not prove the invite secret")
	}
	return nil
}

// Countersign adds the inviter's signature, completing the mutual record.
func (p *PairingProof) Countersign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid identity")
	}
	if !pubKeyOf(priv).Equal(p.Inviter) {
		return fmt.Errorf("inviter key does not match the private key")
	}
	if len(p.AcceptorSig) == 0 {
		return fmt.Errorf("cannot countersign before the acceptor has signed")
	}
	p.InviterSig = Sign(priv, p.payload())
	return nil
}

// VerifyInviter checks the inviter's half without the secret, so a client can
// validate a record it did not mint.
func (p *PairingProof) VerifyInviter() error {
	if len(p.Inviter) != ed25519.PublicKeySize {
		return fmt.Errorf("pairing record has no inviter key")
	}
	if len(p.InviterSig) != ed25519.SignatureSize {
		return fmt.Errorf("pairing record has no inviter signature")
	}
	if !ed25519.Verify(p.Inviter, p.payload(), p.InviterSig) {
		return fmt.Errorf("inviter signature does not match the pairing")
	}
	return nil
}

// Verified reports whether both halves check out without the secret. This is
// the test a daemon applies to every peer before trusting it.
func (p *PairingProof) Verified() bool {
	if p == nil || p.Legacy {
		return false
	}
	return p.VerifyInviter() == nil && ed25519.Verify(p.Acceptor, p.payload(), p.AcceptorSig) &&
		len(p.AcceptorSig) == ed25519.SignatureSize && len(p.AcceptorMAC) == hmacSHA256Size
}

// hmacSHA256Size is the length of an HMAC-SHA256 tag.
const hmacSHA256Size = 32

func pubKeyOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	if len(priv) != ed25519.PrivateKeySize {
		return nil
	}
	return priv.Public().(ed25519.PublicKey)
}

func (p *PairingProof) payload() []byte {
	return PairingPayload(p.InviteID, p.Inviter, p.Acceptor)
}
