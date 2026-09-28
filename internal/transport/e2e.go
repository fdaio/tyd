package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"

	"tyd/internal/auth"
)

// Inner TLS for the relay path.
//
// The relay splices two WebSocket legs with io.Copy and never looks inside, so
// a session that runs the application protocol straight over that splice is
// readable by the relay and by Cloudflare in front of it, and accepts injected
// bytes. Both peers therefore wrap their own leg in TLS right after the splice
// is established. The relay keeps copying ciphertext it cannot read.
//
// The certificate is not the identity here. The relay path has no way to learn
// the peer's certificate fingerprint (the Control Panel's peer record carries
// no daemon id, and a relay-only daemon never publishes an endpoint), so the
// client cannot pin one. Identity comes from the Ed25519 channel binding over
// the TLS exporter instead: see auth.BindingPayload. A relay that terminates
// TLS on one leg and forwards to the other derives a different exporter, so
// the server's binding signature does not verify and the attempt is caught.

// E2EHandshakeTimeout bounds the inner TLS handshake on a relay splice. It is
// generous because the bytes may be crossing a relay on a slow link; the
// caller's dial deadline still applies on top.
const E2EHandshakeTimeout = 30 * time.Second

// E2EServerConfig is the server half: the shared self-signed certificate the
// daemon already publishes for its direct listeners.
func E2EServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// E2EClientConfig is the client half. Certificate verification is off on
// purpose: there is no fingerprint to pin on this path, and pretending to
// verify would only mean verifying the relay's own self-signed certificate.
// The peer is authenticated by the channel binding, which cannot be forged
// without the peer's private key.
func E2EClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("relay peer presented no certificate")
			}
			return nil
		},
	}
}

// ServerE2E is the server half of the handshake.
//
// The first byte distinguishes the two cases: 0x16 starts a TLS handshake
// record, a JSON protocol frame starts with '{'. Probing is only possible on
// this side, because the server speaks second; the client has to send its
// ClientHello before it can read anything, so it cannot wait for the server to
// go first.
func ServerE2E(conn net.Conn, cfg *tls.Config) (*tls.Conn, []byte, error) {
	_ = conn.SetDeadline(time.Now().Add(E2EHandshakeTimeout))
	first, err := peekByte(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return nil, nil, err
	}
	if first == plaintextFrameStart {
		return nil, nil, fmt.Errorf("peer did not start end-to-end TLS: upgrade it, the relay path requires it")
	}
	if cfg == nil {
		cfg = E2EServerConfig(tls.Certificate{})
	}
	return finish(tls.Server(playback(conn, first), cfg))
}

// ClientE2E is the client half. It cannot probe for a plaintext peer (see
// ServerE2E), so an old peer fails the handshake and the server logs it.
func ClientE2E(conn net.Conn, cfg *tls.Config) (*tls.Conn, []byte, error) {
	if cfg == nil {
		cfg = E2EClientConfig()
	}
	return finish(tls.Client(conn, cfg))
}

func finish(tc *tls.Conn) (*tls.Conn, []byte, error) {
	_ = tc.SetDeadline(time.Now().Add(E2EHandshakeTimeout))
	if err := tc.Handshake(); err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("relay e2e handshake: %w", err)
	}
	// Clear the handshake deadline: the session that follows is long-lived and
	// sets its own.
	_ = tc.SetDeadline(time.Time{})
	state := tc.ConnectionState()
	binder, err := Binder(&state)
	if err != nil {
		_ = tc.Close()
		return nil, nil, err
	}
	return tc, binder, nil
}

// plaintextFrameStart is the first byte of a JSON protocol frame.
const plaintextFrameStart = '{'

// peekByte reads the first byte of the stream without losing it.
func peekByte(conn net.Conn) (byte, error) {
	var one [1]byte
	if _, err := io.ReadFull(conn, one[:]); err != nil {
		return 0, err
	}
	return one[0], nil
}

// playback replays bytes already read from conn before reading conn itself.
// crypto/tls must see the whole stream, including the byte the plaintext probe
// consumed, or the handshake record it parses starts one byte late.
func playback(conn net.Conn, consumed ...byte) net.Conn {
	return &prefixConn{Conn: conn, pre: bytes.NewReader(consumed)}
}

type prefixConn struct {
	net.Conn
	pre *bytes.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.pre.Len() > 0 {
		return c.pre.Read(p)
	}
	return c.Conn.Read(p)
}

// Binder derives the channel binding value from a completed TLS 1.3 session.
func Binder(state *tls.ConnectionState) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("no TLS state")
	}
	if state.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("end-to-end TLS must be 1.3, got %x", state.Version)
	}
	out, err := state.ExportKeyingMaterial(auth.BindingLabel, nil, auth.BindingSize)
	if err != nil {
		return nil, fmt.Errorf("channel binding: %w", err)
	}
	return out, nil
}

// VerifyPeerBinding is the client-side check of the server's binding signature.
func VerifyPeerBinding(peer ed25519.PublicKey, nonce, binder, sig []byte) error {
	return auth.VerifyBinding(peer, nonce, binder, sig)
}
