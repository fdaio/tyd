package auth

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func endpointFixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, EndpointRecord) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	rec := NewEndpointRecord("daemon-1", EncodePublic(pub), "203.0.113.7:41234",
		"ABCD1234", "quic", []string{"203.0.113.7:41234", "198.51.100.9:41234"}, now, 90*time.Second, 7)
	return pub, priv, rec
}

func TestEndpointRecordRoundTrip(t *testing.T) {
	pub, priv, rec := endpointFixture(t)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(pub, sig); err != nil {
		t.Fatalf("a freshly signed record did not verify: %v", err)
	}
	if rec.Expired(rec.PublishedAt) {
		t.Error("a record is expired at the moment it was published")
	}
	if !rec.Expired(rec.ExpiresAt.Add(time.Second)) {
		t.Error("a record is still valid past its signed expiry")
	}
}

// The point of the signature: whatever the Control Panel changes, the record no
// longer verifies. Every dial-relevant field is covered.
func TestEndpointRecordRejectsTamperedFields(t *testing.T) {
	pub, priv, base := endpointFixture(t)
	sig, err := base.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(EndpointRecord) EndpointRecord{
		"addr":       func(r EndpointRecord) EndpointRecord { r.Addr = "198.51.100.1:443"; return r },
		"cert_fp":    func(r EndpointRecord) EndpointRecord { r.CertFP = "deadbeef"; return r },
		"transport":  func(r EndpointRecord) EndpointRecord { r.Transport = "tls"; return r },
		"candidates": func(r EndpointRecord) EndpointRecord { r.Candidates = []string{"10.0.0.1:1"}; return r },
		"daemon id":  func(r EndpointRecord) EndpointRecord { r.DaemonID = "daemon-2"; return r },
		"public key": func(r EndpointRecord) EndpointRecord { r.PublicKey = EncodePublic(mustOtherPub(t)); return r },
		"expiry":     func(r EndpointRecord) EndpointRecord { r.ExpiresAt = r.ExpiresAt.Add(24 * time.Hour); return r },
		"sequence":   func(r EndpointRecord) EndpointRecord { r.Seq = 99; return r },
		"version":    func(r EndpointRecord) EndpointRecord { r.Version = 2; return r },
	}
	for name, mutate := range mutations {
		tampered := mutate(base)
		err := tampered.Verify(pub, sig)
		if err == nil {
			t.Errorf("tampering with %s still verified", name)
		}
	}
}

// Extending the expiry is the attack a client cannot catch by itself, because
// the Control Panel is the one serving ExpiresAt. The signed time is what
// counts, and a Control Panel that keeps serving the record runs out.
func TestSignedExpiryIsTheOneThatCounts(t *testing.T) {
	pub, priv, rec := endpointFixture(t)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	now := rec.ExpiresAt.Add(time.Minute)
	if !rec.Expired(now) {
		t.Error("the record should be expired by its own signed time")
	}
	// A Control Panel that reports a later expiry changes nothing, because the
	// client never reads that field.
	if err := rec.Verify(pub, sig); err != nil {
		t.Errorf("an expired record should still verify as authentic, just not be usable: %v", err)
	}
}

func TestEndpointRecordRejectsAnotherKey(t *testing.T) {
	_, priv, rec := endpointFixture(t)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	other := mustOtherPub(t)
	if err := rec.Verify(other, sig); err == nil {
		t.Error("a record verified against a key the client does not trust")
	}
	if err := rec.Verify(nil, sig); err == nil {
		t.Error("a record verified with no pinned key at all")
	}
	if err := rec.Verify(priv.Public().(ed25519.PublicKey), nil); err == nil {
		t.Error("a record with no signature verified")
	}
}

func TestSignRefusesToSignForAnotherKey(t *testing.T) {
	_, _, rec := endpointFixture(t)
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Sign(otherPriv); err == nil {
		t.Error("a daemon signed a record naming somebody else's key")
	}
}

func TestNextEndpointSeqNeverGoesBackwards(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	// A fresh daemon starts above the clock, so a record it signs cannot be
	// mistaken for one a client already saw before the restart.
	first := NextEndpointSeq(0, now)
	if first < uint64(now.Unix()) {
		t.Errorf("first sequence %d is below the clock", first)
	}
	second := NextEndpointSeq(first, now)
	if second <= first {
		t.Errorf("sequence did not advance: %d then %d", first, second)
	}
	// A clock that went backwards must not hand out a number already used.
	back := NextEndpointSeq(second, now.Add(-time.Hour))
	if back <= second {
		t.Errorf("a backwards clock rewound the sequence: %d then %d", second, back)
	}
}

func TestEndpointCanonicalIsUnambiguous(t *testing.T) {
	_, _, rec := endpointFixture(t)
	// Shifting a character between adjacent fields must change the encoding,
	// or a tampered record could collide with an honest one.
	shifted := rec
	shifted.Addr = rec.Addr + "9"
	shifted.CertFP = ""
	if string(shifted.Canonical()) == string(rec.Canonical()) {
		t.Fatal("fields are not separated in the signed encoding")
	}
	// Candidate order is signed as given, since it is the dial order.
	swapped := rec
	swapped.Candidates = []string{rec.Candidates[1], rec.Candidates[0]}
	if string(swapped.Canonical()) == string(rec.Canonical()) {
		t.Error("candidate order is not covered by the signature")
	}
}

func mustOtherPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
