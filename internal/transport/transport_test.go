package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/auth"
)

func TestUnixRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tyd.sock")
	ln, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		tc, ok := c.(Conn)
		if !ok || tc.Info().Transport != KindUnix || tc.Info().TLS {
			errCh <- fmt.Errorf("bad accept info")
			return
		}
		_, _ = c.Write([]byte("ok"))
		errCh <- nil
	}()

	c, err := DialUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Info().Transport != KindUnix {
		t.Fatalf("%+v", c.Info())
	}
	buf := make([]byte, 2)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestTLSRoundTripAndRejectPlain(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	ln, fp, err := ListenTLS("127.0.0.1:0", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	if fp == "" {
		t.Fatal("empty fingerprint")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("tls"))
			_ = c.Close()
		}
	}()

	c, err := DialTLS(addr, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Info().TLS || c.Info().Transport != KindTLS {
		t.Fatalf("%+v", c.Info())
	}
	buf := make([]byte, 3)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	_ = c.Close()
	if err != nil || string(buf[:n]) != "tls" {
		t.Fatalf("got %q %v", buf[:n], err)
	}

	otherCert := filepath.Join(dir, "other.crt")
	otherKey := filepath.Join(dir, "other.key")
	if _, err := EnsureServerCert(otherCert, otherKey); err != nil {
		t.Fatal(err)
	}
	if _, err := DialTLS(addr, otherCert); err == nil {
		t.Fatal("expected untrusted cert")
	}

	// Plain TCP must not complete tyd's TLS client dial.
	pc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(400 * time.Millisecond))
	tlsConn := tls.Client(pc, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		ServerName:         "tyd",
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return fmt.Errorf("reject")
		},
	})
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("expected handshake failure with reject verifier")
	}
	_ = pc.Close()
}

func TestChannelBinderFollowsTheSession(t *testing.T) {
	// A unix socket has no TLS session, so it has nothing to bind to.
	unixPath := fmt.Sprintf("/tmp/tyd-bind-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%1_000_000)
	unixLn, err := ListenUnix(unixPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixLn.Close()
	t.Cleanup(func() { _ = os.Remove(unixPath) })
	go func() {
		c, err := unixLn.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	unixConn, err := DialUnix(unixPath)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := ChannelBinder(unixConn)
	if binder != nil || err != nil {
		t.Fatalf("unix binding=%x err=%v", binder, err)
	}
	_ = unixConn.Close()

	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	ln, _, err := ListenTLS("127.0.0.1:0", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// The server side of a TLS handshake only starts when something reads or
	// writes, so the listener has to keep taking connections and answer them or
	// the dials below never finish.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
		}
	}()

	dial := func() Conn {
		t.Helper()
		c, err := DialTLS(ln.Addr().String(), cert)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first, second := dial(), dial()
	defer first.Close()
	defer second.Close()

	firstBinder, err := ChannelBinder(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBinder, err := ChannelBinder(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstBinder) != auth.BindingSize || len(secondBinder) != auth.BindingSize {
		t.Fatalf("binding lengths %d and %d", len(firstBinder), len(secondBinder))
	}
	if bytes.Equal(firstBinder, secondBinder) {
		t.Fatal("two TLS sessions derived the same binding")
	}

	// A wrapped conn reports the binding of the session underneath it, so the
	// value does not depend on who holds the connection.
	wrapped, err := ChannelBinder(Wrap(first, Info{Transport: KindTLS, TLS: true}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, firstBinder) {
		t.Fatal("wrapping the connection changed its binding")
	}
}

// A connection whose binding cannot be derived must be refused, not
// authenticated over the bare nonce: that is the signature a peer carries
// between daemons.
func TestChannelBinderRefusesAnUnknownConnection(t *testing.T) {
	mine, peer := net.Pipe()
	defer mine.Close()
	defer peer.Close()
	if binder, err := ChannelBinder(mine); err == nil {
		t.Fatalf("accepted a connection with no binding: %x", binder)
	}
}

func TestDefaultTLSAddr(t *testing.T) {
	if DefaultTLSAddr != "127.0.0.1:61211" {
		t.Fatalf("%s", DefaultTLSAddr)
	}
}
