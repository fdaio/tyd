package client

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// A paired peer that is compromised must not be able to become the client on
// another daemon. It used to: it took the challenge meant for the other
// daemon, sent it here as its own, and the signature that came back verified
// there, because the client signed whatever bytes it was handed and nothing
// tied that signature to the connection it was made on.

// startDaemon runs a daemon that trusts the client identity and listens over
// a direct transport. It returns its endpoint and the certificate to pin.
func startDaemon(t *testing.T, kind transport.Kind, trust *auth.Store) (ep Endpoint, certPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	cfg := server.Config{
		CertPath: certPath,
		KeyPath:  filepath.Join(dir, "server.key"),
		Mgr:      session.NewManager(),
		Trust:    trust,
	}
	switch kind {
	case transport.KindQUIC:
		cfg.DataListen = "127.0.0.1:0"
	default:
		cfg.Listen = "127.0.0.1:0"
	}
	srv := server.NewWithConfig(cfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ep = Endpoint{Kind: kind, Address: srv.ListenAddr(), CertFP: srv.TLSFingerprintFull()}
	if kind == transport.KindQUIC {
		ep.Address = srv.DataPlaneAddr()
	}
	if err := WaitReady(ep, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return ep, certPath
}

// dialDirect connects to a direct endpoint the way an attacker would: to
// collect a challenge, or to answer one.
func dialDirect(t *testing.T, ep Endpoint, certPath string) transport.Conn {
	t.Helper()
	var (
		conn transport.Conn
		err  error
	)
	if ep.Kind == transport.KindQUIC {
		conn, err = transport.DialQUICFingerprint(ep.Address, ep.CertFP)
	} else {
		conn, err = transport.DialTLS(ep.Address, certPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// openChallenged opens a connection and leaves it waiting for an auth response.
// A daemon challenges every connection, authenticated or not, so any peer can
// collect a challenge, and the attacker needs the connection still open to
// answer it later with a signature taken from somewhere else.
func openChallenged(t *testing.T, ep Endpoint, certPath string) (transport.Conn, []byte) {
	t.Helper()
	conn := dialDirect(t, ep, certPath)
	f, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeChallenge {
		t.Fatalf("got %q, want a challenge", f.Type)
	}
	return conn, f.Data
}

// answerAuth replies to the challenge the connection is holding and reports
// what the daemon answered.
func answerAuth(t *testing.T, conn transport.Conn, key ed25519.PrivateKey, sig []byte) protocol.Frame {
	t.Helper()
	err := protocol.WriteFrame(conn, protocol.Frame{
		Type:      protocol.TypeAuth,
		PublicKey: key.Public().(ed25519.PublicKey),
		Data:      sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// impostor stands in for a daemon the client trusts: it accepts the client on
// its own listener and challenges it with whatever bytes it was handed.
type impostor struct {
	ep       Endpoint
	certPath string
	sig      chan []byte
}

func startImpostor(t *testing.T, kind transport.Kind, challenge []byte) *impostor {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "peer.crt")
	keyPath := filepath.Join(dir, "peer.key")
	var (
		ln  net.Listener
		fp  string
		err error
	)
	if kind == transport.KindQUIC {
		ln, fp, err = transport.ListenQUIC("127.0.0.1:0", certPath, keyPath)
	} else {
		ln, fp, err = transport.ListenTLS("127.0.0.1:0", certPath, keyPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	imp := &impostor{
		ep:       Endpoint{Kind: kind, Address: ln.Addr().String(), CertFP: fp},
		certPath: certPath,
		sig:      make(chan []byte, 1),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go imp.serve(conn, challenge)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return imp
}

func (i *impostor) serve(conn net.Conn, challenge []byte) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// The version, because a client refuses to sign for a daemon it cannot
	// speak. Without it this test would still pass, but for the wrong reason:
	// the impostor would get no signature because the client walked away rather
	// than because the binding rejected the signature.
	if err := protocol.WriteFrame(conn, protocol.Frame{
		Type:    protocol.TypeChallenge,
		Version: auth.CurrentVersion,
		Data:    challenge,
	}); err != nil {
		return
	}
	f, err := protocol.ReadFrame(conn)
	if err != nil || f.Type != protocol.TypeAuth {
		return
	}
	i.sig <- f.Data
}

// signatureHere makes the client authenticate to the impostor and returns the
// signature the impostor collected. The dial itself may fail: the impostor
// hangs up once it has what it came for.
func signatureHere(t *testing.T, imp *impostor, key ed25519.PrivateKey) []byte {
	t.Helper()
	_, _ = Dial(imp.ep, key)
	select {
	case sig := <-imp.sig:
		if len(sig) != ed25519.SignatureSize {
			t.Fatalf("client signed %d bytes", len(sig))
		}
		return sig
	case <-time.After(10 * time.Second):
		t.Fatal("the impostor never got a signature")
		return nil
	}
}

func TestChallengeLiftedToAnotherDaemonIsRefused(t *testing.T) {
	for _, kind := range []transport.Kind{transport.KindTLS, transport.KindQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			_, clientKey, err := auth.Generate()
			if err != nil {
				t.Fatal(err)
			}
			trust := auth.NewStore()
			trust.Add("client", clientKey.Public().(ed25519.PublicKey), auth.AllGlobal)

			victim, victimCert := startDaemon(t, kind, trust)
			victimConn, stolen := openChallenged(t, victim, victimCert)

			// The impostor challenges the client with the challenge it is holding
			// from the victim daemon, and collects the signature that comes back.
			imp := startImpostor(t, kind, stolen)
			sig := signatureHere(t, imp, clientKey)

			// Answering the victim with that signature must not log in: the
			// signature covers the session it was made on, and this is another.
			if f := answerAuth(t, victimConn, clientKey, sig); f.Type != protocol.TypeError {
				t.Fatalf("a signature made for another connection was accepted: %q", f.Type)
			}

			// A login the client makes over its own session with that daemon still
			// works, so the refusal above is the binding and not a broken path.
			conn, err := Dial(victim, clientKey)
			if err != nil {
				t.Fatalf("direct %s login refused: %v", kind, err)
			}
			_ = conn.Close()
		})
	}
}

func TestClientRefusesAChallengeThatIsNotANonce(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33, 64} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			_, key, err := auth.Generate()
			if err != nil {
				t.Fatal(err)
			}
			mine, peer := net.Pipe()
			defer mine.Close()
			defer peer.Close()
			// The peer accepts whatever it is sent, so a client that signs
			// anyway reports success and the test fails on the signature rather
			// than on a timeout.
			go func() {
				if err := protocol.WriteFrame(peer, protocol.Frame{
					Type: protocol.TypeChallenge,
					Data: make([]byte, size),
				}); err != nil {
					return
				}
				if f, err := protocol.ReadFrame(peer); err == nil && f.Type == protocol.TypeAuth {
					_ = protocol.WriteFrame(peer, protocol.Frame{Type: protocol.TypeOK})
				}
			}()
			conn := &Conn{nc: transport.Wrap(mine, transport.Info{Transport: transport.KindUnix})}
			if err := conn.AuthenticateBound(key, nil); err == nil {
				t.Fatalf("client signed a %d byte challenge", size)
			}
		})
	}
}
