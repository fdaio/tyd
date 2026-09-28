package auth

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Signed endpoint records.
//
// A daemon publishes where it can be reached: an address, a certificate
// fingerprint, a candidate list, a transport. The client dials whatever it is
// told. That record came from the Control Panel, and it was never signed, so a
// Control Panel could point a client at a machine it controls and hand over the
// matching certificate fingerprint -- the client would have no way to tell.
//
// The signature makes the Control Panel a courier: it can forward a record,
// withhold it, or stop serving one, but the contents are the daemon's. The
// client checks the signature against the peer key it learned at pairing, which
// is the same anchor REQ-032 established for the session layer.

// EndpointProofVersion is the record format. Bump it when the signed layout
// changes so an old record cannot be read as a new one.
const EndpointProofVersion = 1

// EndpointRecord is the material a daemon signs. It is self-contained: the
// expiry and the sequence come from the signer, because the Control Panel's own
// view of either is not something a client should act on.
type EndpointRecord struct {
	Version     int       `json:"version"`
	DaemonID    string    `json:"daemon_id"`
	PublicKey   string    `json:"public_key"`
	Addr        string    `json:"addr"`
	CertFP      string    `json:"cert_fp"`
	Transport   string    `json:"transport,omitempty"`
	Candidates  []string  `json:"candidates,omitempty"`
	PublishedAt time.Time `json:"published_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Seq         uint64    `json:"seq"`
}

// NewEndpointRecord fills in the parts a client cannot check for itself. ttl
// bounds how long the record may be used; seq must increase on every publish.
func NewEndpointRecord(daemonID, publicKey, addr, certFP, transport string, candidates []string, publishedAt time.Time, ttl time.Duration, seq uint64) EndpointRecord {
	return EndpointRecord{
		Version:     EndpointProofVersion,
		DaemonID:    strings.TrimSpace(daemonID),
		PublicKey:   strings.TrimSpace(publicKey),
		Addr:        strings.TrimSpace(addr),
		CertFP:      strings.ToLower(strings.TrimSpace(certFP)),
		Transport:   strings.ToLower(strings.TrimSpace(transport)),
		Candidates:  append([]string(nil), candidates...),
		PublishedAt: publishedAt.UTC().Truncate(time.Second),
		ExpiresAt:   publishedAt.UTC().Add(ttl).Truncate(time.Second),
		Seq:         seq,
	}
}

// Sign returns the record's signature over its canonical encoding.
func (r EndpointRecord) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if r.PublicKey != "" && r.PublicKey != EncodePublic(pub) {
		return nil, fmt.Errorf("record names a different key than the signer")
	}
	return Sign(priv, r.Canonical()), nil
}

// Verify checks the signature against the key the client already trusts. The
// caller passes that key in rather than looking it up, so a record can never be
// validated against a key the record itself names.
func (r EndpointRecord) Verify(pub ed25519.PublicKey, sig []byte) error {
	if r.Version != EndpointProofVersion {
		return fmt.Errorf("unsupported endpoint record version %d", r.Version)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("no pinned key for this peer")
	}
	if r.PublicKey != "" && r.PublicKey != EncodePublic(pub) {
		return fmt.Errorf("endpoint record is for a different key")
	}
	if strings.TrimSpace(r.Addr) == "" || strings.TrimSpace(r.CertFP) == "" {
		return fmt.Errorf("endpoint record is incomplete")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("endpoint record has no signature")
	}
	if !ed25519.Verify(pub, r.Canonical(), sig) {
		return fmt.Errorf("endpoint record signature does not match; the Control Panel may be substituting this endpoint")
	}
	return nil
}

// Expired reports whether the record is past its own signed expiry. The signed
// time is the one that counts: a Control Panel that keeps serving a record
// cannot extend its life.
func (r EndpointRecord) Expired(now time.Time) bool {
	return !now.UTC().Before(r.ExpiresAt.UTC())
}

// Canonical is the exact byte string that is signed. Every field is length
// prefixed or fixed width, so no combination of values can be rearranged into
// another record that signs the same.
func (r EndpointRecord) Canonical() []byte {
	var b []byte
	b = append(b, byte(EndpointProofVersion))
	b = appendField(b, []byte(r.DaemonID))
	b = appendField(b, []byte(r.PublicKey))
	b = appendField(b, []byte(r.Addr))
	b = appendField(b, []byte(r.CertFP))
	b = appendField(b, []byte(r.Transport))
	// Candidate order is the dial order, so it is signed as given rather than
	// sorted; sorting would hide a reordering.
	for _, c := range r.Candidates {
		b = appendField(b, []byte(strings.TrimSpace(c)))
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], r.Seq)
	b = append(b, seq[:]...)
	b = appendTime(b, r.PublishedAt)
	b = appendTime(b, r.ExpiresAt)
	return b
}

func appendField(dst, v []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	dst = append(dst, n[:]...)
	return append(dst, v...)
}

func appendTime(dst []byte, t time.Time) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(t.UTC().Unix()))
	return append(dst, n[:]...)
}

// NextEndpointSeq keeps a publish sequence monotonic across restarts. Seeding
// from the clock means a restarted daemon never reissues a number a client has
// already seen and rejected as a replay.
func NextEndpointSeq(prev uint64, now time.Time) uint64 {
	clock := uint64(now.UTC().Unix())
	if prev < clock {
		return clock
	}
	return prev + 1
}
