package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const tydQUICALPN = "tyd"

// ListenQUIC listens for QUIC. Accept returns a server-opened bidirectional
// stream so the peer can speak first (challenge/auth) without a client write.
func ListenQUIC(addr, certPath, keyPath string) (net.Listener, string, error) {
	cert, err := EnsureServerCert(certPath, keyPath)
	if err != nil {
		return nil, "", err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, "", err
	}
	fp := Fingerprint(leaf)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{tydQUICALPN},
	}
	ql, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		MaxIdleTimeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, "", err
	}
	return &quicListener{ql: ql, fp: fp}, fp, nil
}

type quicListener struct {
	ql *quic.Listener
	fp string
}

func (l *quicListener) Accept() (net.Conn, error) {
	ctx := context.Background()
	sess, err := l.ql.Accept(ctx)
	if err != nil {
		return nil, err
	}
	// Server opens the stream so tyd can send the auth challenge first.
	// (Client-opened streams stay invisible to AcceptStream until the client
	// writes, which deadlocks a server-speaks-first protocol.)
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		_ = sess.CloseWithError(0, "open stream failed")
		return nil, err
	}
	return Wrap(&quicStreamConn{stream: stream, sess: sess}, Info{
		Transport: KindQUIC,
		TLS:       true,
		CertFP:    ShortFP(l.fp),
	}), nil
}

func (l *quicListener) Close() error   { return l.ql.Close() }
func (l *quicListener) Addr() net.Addr { return l.ql.Addr() }

// DialQUICFingerprint dials QUIC and pins the server by SHA-256 cert fingerprint (hex).
func DialQUICFingerprint(addr, certFP string) (Conn, error) {
	return DialQUICFingerprintContext(context.Background(), addr, certFP)
}

// DialQUICFingerprintContext is DialQUICFingerprint with cancellation.
func DialQUICFingerprintContext(ctx context.Context, addr, certFP string) (Conn, error) {
	wantFP := strings.ToLower(strings.TrimSpace(certFP))
	if wantFP == "" {
		return nil, fmt.Errorf("quic: empty certificate fingerprint")
	}
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{tydQUICALPN},
		ServerName:         "tyd",
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("quic: no server certificates")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			got := Fingerprint(cert)
			if got != wantFP {
				return fmt.Errorf("quic: untrusted server certificate (fp %s)", ShortFP(got))
			}
			return nil
		},
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sess, err := quic.DialAddr(dctx, addr, tlsConf, &quic.Config{
		MaxIdleTimeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	stream, err := sess.AcceptStream(dctx)
	if err != nil {
		_ = sess.CloseWithError(0, "stream accept failed")
		return nil, fmt.Errorf("quic accept stream %s: %w", addr, err)
	}
	return Wrap(&quicStreamConn{stream: stream, sess: sess}, Info{
		Transport: KindQUIC,
		TLS:       true,
		CertFP:    ShortFP(wantFP),
	}), nil
}

type quicStreamConn struct {
	stream *quic.Stream
	sess   *quic.Conn
}

func (c *quicStreamConn) Read(b []byte) (int, error)         { return c.stream.Read(b) }
func (c *quicStreamConn) Write(b []byte) (int, error)        { return c.stream.Write(b) }
func (c *quicStreamConn) Close() error                       { return c.stream.Close() }
func (c *quicStreamConn) LocalAddr() net.Addr                { return c.sess.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.sess.RemoteAddr() }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
