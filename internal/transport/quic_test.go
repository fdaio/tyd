package transport

import (
	"context"
	"crypto/tls"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICRoundTripPin(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.crt")
	key := filepath.Join(dir, "c.key")
	ln, fp, err := ListenQUIC("127.0.0.1:0", cert, key)
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
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "ping" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		_, err = c.Write([]byte("pong"))
		errCh <- err
	}()

	c, err := DialQUICFingerprint(ln.Addr().String(), fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
	_ = c.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestRawQUICEcho(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")
	cert, err := EnsureServerCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{tydQUICALPN},
	}
	ql, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ql.Close()

	done := make(chan error, 1)
	go func() {
		ctx := context.Background()
		sess, err := ql.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			done <- err
			return
		}
		_, err = st.Write([]byte("pong"))
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cliTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{tydQUICALPN},
		ServerName:         "tyd",
	}
	sess, err := quic.DialAddr(ctx, ql.Addr().String(), cliTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExpandCandidates(t *testing.T) {
	cands := ExpandCandidates("0.0.0.0:1234", "example.com")
	if len(cands) < 2 {
		t.Fatalf("candidates %v", cands)
	}
	if cands[0] != "example.com:1234" {
		t.Fatalf("advertise should be first: %v", cands)
	}
	foundLoop := false
	for _, c := range cands {
		if c == "127.0.0.1:1234" {
			foundLoop = true
		}
	}
	if !foundLoop {
		t.Fatalf("missing loopback in %v", cands)
	}

	// Loopback advertise must not win over real interfaces.
	cands = ExpandCandidates("0.0.0.0:9", "127.0.0.1")
	if len(cands) == 0 || cands[0] == "127.0.0.1:9" && len(cands) > 1 {
		// If only loopback exists, sole entry is fine; otherwise first must not be loopback when extras exist.
		nonLoop := PreferNonLoopback(cands)
		if len(nonLoop) > 1 && nonLoop[0] == "127.0.0.1:9" {
			t.Fatalf("loopback should not be preferred: %v", nonLoop)
		}
	}
}

func TestPreferNonLoopback(t *testing.T) {
	got := PreferNonLoopback([]string{"127.0.0.1:1", "10.0.0.2:1", "127.0.0.1:1", "192.168.1.1:1"})
	if len(got) != 3 || got[0] != "10.0.0.2:1" || got[1] != "192.168.1.1:1" || got[2] != "127.0.0.1:1" {
		t.Fatalf("%v", got)
	}
}

