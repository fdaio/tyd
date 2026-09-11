package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
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

func TestDefaultTLSAddr(t *testing.T) {
	if DefaultTLSAddr != "127.0.0.1:61211" {
		t.Fatalf("%s", DefaultTLSAddr)
	}
}
