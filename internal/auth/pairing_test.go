package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustSecret(t *testing.T) []byte {
	t.Helper()
	s, err := NewInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The token the operator copies must carry enough for the acceptor to tell the
// Control Panel's answer from the truth.
func TestInviteTokenCarriesTheInviterKeyHash(t *testing.T) {
	inviter, _ := mustKey(t)
	secret := mustSecret(t)

	tok, err := FormatInviteToken("inv-123", secret, inviter)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInviteToken(tok.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.InviteID != "inv-123" {
		t.Errorf("invite id = %q", parsed.InviteID)
	}
	if string(parsed.Secret) != string(secret) {
		t.Error("secret did not survive the round trip")
	}
	if !parsed.MatchesInviter(inviter) {
		t.Error("the inviter's own key does not match its token")
	}

	// A Control Panel that substitutes its own key fails here, and this is the
	// only place that substitution is caught.
	attacker, _ := mustKey(t)
	if parsed.MatchesInviter(attacker) {
		t.Error("a substituted inviter key matched the token")
	}
}

func TestParseInviteTokenRejectsMalformed(t *testing.T) {
	inviter, _ := mustKey(t)
	secret := mustSecret(t)
	good, err := FormatInviteToken("id", secret, inviter)
	if err != nil {
		t.Fatal(err)
	}
	s := good.String()
	parts := strings.Split(s, ".")

	bad := map[string]string{
		"no secret half":  parts[0],
		"empty secret":    parts[0] + ".." + parts[2],
		"short secret":    parts[0] + ".abcd." + parts[2],
		"non-hex secret":  parts[0] + ".zzzz." + parts[2],
		"non-hex hash":    parts[0] + "." + parts[1] + ".zzzz",
		"empty":           "",
		"extra segments":  s + ".extra",
		"whitespace only": "   ",
	}
	for name, token := range bad {
		if _, err := ParseInviteToken(token); err == nil {
			t.Errorf("%s: accepted %q", name, token)
		}
	}
}

func TestPairingProofRoundTrip(t *testing.T) {
	inviterPub, inviterPriv := mustKey(t)
	acceptorPub, acceptorPriv := mustKey(t)
	secret := mustSecret(t)

	tok, err := FormatInviteToken("inv-9", secret, inviterPub)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPairingProof(tok.InviteID, inviterPub, acceptorPub)
	if p.Verified() {
		t.Error("an unsigned record claimed to be verified")
	}

	if err := p.SignAcceptor(acceptorPriv, secret); err != nil {
		t.Fatal(err)
	}
	if p.Verified() {
		t.Error("a half-signed record claimed to be verified")
	}
	// The inviter can check the acceptor's half with the secret it minted.
	if err := p.VerifyAcceptor(secret); err != nil {
		t.Fatalf("inviter could not verify the acceptor: %v", err)
	}

	if err := p.Countersign(inviterPriv); err != nil {
		t.Fatal(err)
	}
	if !p.Verified() {
		t.Error("a fully signed record was not verified")
	}
	if err := p.VerifyInviter(); err != nil {
		t.Errorf("inviter signature: %v", err)
	}
}

// The whole point of the record: the Control Panel holds no secret, so it
// cannot assemble one, and it cannot take the inviter's signature and reuse it
// for a different acceptor.
func TestPairingProofRejectsAForgedRecord(t *testing.T) {
	inviterPub, _ := mustKey(t)
	acceptorPub, acceptorPriv := mustKey(t)
	secret := mustSecret(t)
	attackerPub, attackerPriv := mustKey(t)

	honest := NewPairingProof("inv-1", inviterPub, acceptorPub)
	if err := honest.SignAcceptor(acceptorPriv, secret); err != nil {
		t.Fatal(err)
	}

	// The CP knows the acceptor's real signature but not the secret.
	if err := honest.VerifyAcceptor(mustSecret(t)); err == nil {
		t.Error("verification passed without the real secret")
	}

	// Swapping in a key the CP holds breaks the signature.
	swapped := *honest
	swapped.Acceptor = append(ed25519.PublicKey(nil), attackerPub...)
	if err := swapped.VerifyAcceptor(secret); err == nil {
		t.Error("a swapped acceptor key verified")
	}

	// Replaying the acceptor's half onto another invite id breaks it too.
	replayed := *honest
	replayed.InviteID = "inv-2"
	if err := replayed.VerifyAcceptor(secret); err == nil {
		t.Error("a record replayed onto another invite verified")
	}

	// A Control Panel that wants a key of its own trusted builds a record for
	// itself. It can sign its own half -- it holds that key -- but it cannot
	// produce the MAC, because the MAC is keyed by a secret it never saw. So
	// the inviter refuses the record and never countersigns, and without the
	// countersignature the record does not verify.
	forged := NewPairingProof("inv-1", inviterPub, attackerPub)
	if err := forged.SignAcceptor(attackerPriv, secret); err != nil {
		t.Fatalf("the CP can of course sign with a key it holds: %v", err)
	}
	inviterSide := NewPairingProof("inv-1", inviterPub, attackerPub)
	inviterSide.AcceptorSig = forged.AcceptorSig
	if err := inviterSide.VerifyAcceptor(secret); err == nil {
		t.Fatal("a record the CP assembled verified against the inviter's secret")
	}

	// Even a record carrying a real inviter signature is not enough on its own.
	partial := NewPairingProof("inv-1", inviterPub, attackerPub)
	partial.AcceptorSig = append([]byte(nil), honest.AcceptorSig...)
	partial.AcceptorMAC = append([]byte(nil), honest.AcceptorMAC...)
	if partial.Verified() {
		t.Error("a record with a borrowed acceptor half reported itself verified")
	}
	// And the honest record, transplanted onto the CP's key, does not verify
	// either: the payload covers the acceptor.
	transplanted := *honest
	transplanted.Acceptor = append(ed25519.PublicKey(nil), attackerPub...)
	if transplanted.Verified() {
		t.Error("an honest record with a swapped acceptor verified")
	}
}

func TestCountersignRequiresAcceptorFirst(t *testing.T) {
	inviterPub, inviterPriv := mustKey(t)
	acceptorPub, _ := mustKey(t)
	p := NewPairingProof("inv-1", inviterPub, acceptorPub)
	if err := p.Countersign(inviterPriv); err == nil {
		t.Error("the inviter countersigned a record the acceptor had not signed")
	}
}

func TestPairingPayloadIsUnambiguous(t *testing.T) {
	inviter, _ := mustKey(t)
	acceptorA, _ := mustKey(t)
	acceptorB, _ := mustKey(t)
	// Different invite ids over the same keys must not sign the same bytes.
	if string(PairingPayload("a", inviter, acceptorA)) == string(PairingPayload("b", inviter, acceptorA)) {
		t.Error("invite id is not covered by the signed payload")
	}
	// Nor may the two keys be swapped.
	if string(PairingPayload("a", inviter, acceptorA)) == string(PairingPayload("a", acceptorA, inviter)) {
		t.Error("inviter and acceptor are not separated in the payload")
	}
	_ = acceptorB
}

func TestVerifiedRejectsALegacyRecord(t *testing.T) {
	inviterPub, inviterPriv := mustKey(t)
	acceptorPub, acceptorPriv := mustKey(t)
	secret := mustSecret(t)
	p := NewPairingProof("inv-1", inviterPub, acceptorPub)
	if err := p.SignAcceptor(acceptorPriv, secret); err != nil {
		t.Fatal(err)
	}
	if err := p.Countersign(inviterPriv); err != nil {
		t.Fatal(err)
	}
	if !p.Verified() {
		t.Fatal("fixture is not verified")
	}
	// A legacy peer is trusted by a separate, explicitly weaker path; Verified
	// must never be the thing that admits it.
	p.Legacy = true
	if p.Verified() {
		t.Error("a legacy record reported itself as verified")
	}
}

func TestFormatInviteTokenValidatesInput(t *testing.T) {
	pub, _ := mustKey(t)
	if _, err := FormatInviteToken("", mustSecret(t), pub); err == nil {
		t.Error("accepted an empty invite id")
	}
	if _, err := FormatInviteToken("id", []byte("short"), pub); err == nil {
		t.Error("accepted a short secret")
	}
}
