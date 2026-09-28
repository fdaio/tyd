package relay_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/protocol"
	"tyd/internal/relay"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// These tests replace the relay with a hostile one: it speaks the same
// rendezvous protocol, splices the two peers as the real hub does, and then
// does whatever the mode says -- read every byte, alter one, inject some, or
// terminate TLS on both legs and forward the plaintext.
//
// They are the regression net for how this path used to work. The session ran
// over the splice in cleartext with no integrity, so the relay, and Cloudflare
// in front of it, could read every keystroke and inject bytes into the shell.

// spliceMode is what the hostile relay does with the spliced stream.
type spliceMode int

const (
	// spliceRecord copies the stream and keeps every byte, in both directions.
	spliceRecord spliceMode = iota
	// spliceTamper flips a bit in the first client-to-server chunk.
	spliceTamper
	// spliceInject prepends a plaintext protocol frame to the first
	// server-to-client chunk, which is what an injected command used to be.
	spliceInject
	// spliceMITM terminates TLS on the client's leg with a certificate of its
	// own and opens a real inner-TLS session to the server, forwarding the
	// decrypted stream in between.
	spliceMITM
)

// hostileRelay is a relay that betrays the peers it splices.
type hostileRelay struct {
	url  string
	mode spliceMode
	logf func(string, ...any)

	mu      sync.Mutex
	up      []byte // client -> server
	down    []byte // server -> client
	used    bool
	offered chan struct{}
	once    sync.Once

	offers  map[string]net.Conn
	tickets map[string]chan net.Conn
	certDir string
}

func startHostileRelay(t *testing.T, mode spliceMode) *hostileRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &hostileRelay{
		url:     "http://" + ln.Addr().String(),
		mode:    mode,
		logf:    t.Logf,
		offers:  map[string]net.Conn{},
		tickets: map[string]chan net.Conn{},
	}
	srv := &http.Server{Handler: http.HandlerFunc(h.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return h
}

func (h *hostileRelay) log(format string, args ...any) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}

func (h *hostileRelay) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.Header.Get("Upgrade") == "" {
		_, _ = w.Write([]byte("tyd-relay websocket\n"))
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	// A background context so the conn outlives this handler, as the real relay
	// does.
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	msg, err := relay.ReadMsg(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	switch msg.Type {
	case relay.TypeOffer:
		h.mu.Lock()
		h.offers[msg.DaemonID] = conn
		h.mu.Unlock()
		if err := relay.WriteMsg(conn, relay.Msg{Type: relay.TypeOK}); err != nil {
			return
		}
		h.holdOffer(conn)
	case relay.TypeDial:
		h.mu.Lock()
		o, ok := h.offers[msg.PeerID]
		h.mu.Unlock()
		if !ok {
			_ = relay.WriteMsg(conn, relay.Msg{Type: relay.TypeError, Error: "peer offline"})
			return
		}
		ticket := "hostile-" + msg.PeerID
		ch := make(chan net.Conn, 1)
		h.mu.Lock()
		h.tickets[ticket] = ch
		h.mu.Unlock()
		if err := relay.WriteMsg(o, relay.Msg{Type: relay.TypeIncoming, Ticket: ticket}); err != nil {
			return
		}
		if err := relay.WriteMsg(conn, relay.Msg{Type: relay.TypeOK, Ticket: ticket}); err != nil {
			return
		}
		server, ok := <-ch
		if !ok {
			return
		}
		if err := relay.WriteMsg(server, relay.Msg{Type: relay.TypeOK, Ticket: ticket}); err != nil {
			return
		}
		h.splice(conn, server)
	case relay.TypeAccept:
		h.mu.Lock()
		ch, ok := h.tickets[msg.Ticket]
		h.mu.Unlock()
		if !ok {
			_ = relay.WriteMsg(conn, relay.Msg{Type: relay.TypeError, Error: "unknown ticket"})
			return
		}
		ch <- conn
		<-time.After(30 * time.Second) // hold the leg open for the splice
	default:
		_ = relay.WriteMsg(conn, relay.Msg{Type: relay.TypeError, Error: "unknown type"})
	}
}

// holdOffer keeps the offer's handler alive. The daemon reads TypeIncoming
// messages on this leg for the rest of the test, and the real hub's handler
// blocks for the same reason: if it returned, the WebSocket would close.
func (h *hostileRelay) holdOffer(conn net.Conn) {
	for {
		if _, err := relay.ReadMsg(conn); err != nil {
			return
		}
	}
}

func (h *hostileRelay) saw(direction string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if direction == "up" {
		return append([]byte(nil), h.up...)
	}
	return append([]byte(nil), h.down...)
}

func (h *hostileRelay) paths() (string, string) {
	dir, err := os.MkdirTemp("", "tyd-hostile")
	if err != nil {
		return "", ""
	}
	h.mu.Lock()
	h.certDir = dir
	h.mu.Unlock()
	return filepath.Join(dir, "crt"), filepath.Join(dir, "key")
}

// splice is where the real hub calls io.Copy twice. Everything else here is the
// betrayal.
func (h *hostileRelay) splice(client, server net.Conn) {
	h.mu.Lock()
	h.used = true
	h.mu.Unlock()

	if h.mode == spliceMITM {
		h.mitm(client, server)
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.pump(server, client, true) }()
	go func() { defer wg.Done(); h.pump(client, server, false) }()
	wg.Wait()
}

func (h *hostileRelay) pump(dst, src net.Conn, fromClient bool) {
	buf := make([]byte, 16*1024)
	first := true
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			h.mu.Lock()
			if fromClient {
				h.up = append(h.up, chunk...)
			} else {
				h.down = append(h.down, chunk...)
			}
			h.mu.Unlock()
			if first {
				switch h.mode {
				case spliceTamper:
					if fromClient && len(chunk) > 8 {
						chunk[len(chunk)/2] ^= 0x40
					}
				case spliceInject:
					if !fromClient {
						// What an injected command looked like before the
						// session was encrypted.
						chunk = append([]byte(`{"type":"write","data":"aW5qZWN0ZWQK"}`), chunk...)
					}
				}
				first = false
			}
			if _, werr := dst.Write(chunk); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// mitm terminates the client's TLS with a certificate of its own and opens a
// real inner-TLS session to the server, forwarding the plaintext in between.
// The client is served competently, by someone who is not the peer.
func (h *hostileRelay) mitm(client, server net.Conn) {
	crt, key := h.paths()
	cert, err := transport.EnsureServerCert(crt, key)
	if err != nil {
		h.log("hostile relay: certificate: %v", err)
		return
	}
	front := tls.Server(client, transport.E2EServerConfig(cert))
	_ = front.SetDeadline(time.Now().Add(20 * time.Second))
	if err := front.Handshake(); err != nil {
		h.log("hostile relay: client handshake: %v", err)
		return
	}
	back, _, err := transport.ClientE2E(server, nil)
	if err != nil {
		h.log("hostile relay: server session: %v", err)
		return
	}
	h.log("hostile relay: relaying plaintext between two TLS sessions")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = copyPlain(front, back) }()
	go func() { defer wg.Done(); _, _ = copyPlain(back, front) }()
	wg.Wait()
}

func copyPlain(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 16*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// relayFixture is a daemon offering on a relay plus a client identity. The
// client pins peerPub: the relay path has no certificate fingerprint to pin,
// so the peer's Ed25519 key is the anchor.
type relayFixture struct {
	relayURL string
	key      ed25519.PrivateKey
	peerPub  ed25519.PublicKey
	daemonID string
}

func startFixture(t *testing.T, daemonID, relayURL string) relayFixture {
	t.Helper()
	// A short socket path: t.TempDir() embeds the long test name and can pass
	// the ~104-byte sun_path limit.
	dir, err := os.MkdirTemp("", "tyde2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	peerPub, peerPriv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientPriv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(dir, "trust.json")
	if err := auth.WriteBootstrapTrust(trustPath, "local", peerPub); err != nil {
		t.Fatal(err)
	}
	trust, err := auth.LoadStore(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	// The client authenticates too, so its key has to be trusted as well.
	trust.EnsurePeer("client", clientPub, auth.AllGlobal)
	cert, err := transport.EnsureServerCert(filepath.Join(dir, "crt"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewWithConfig(server.Config{
		Socket: filepath.Join(dir, "s.sock"),
		Mgr:    session.NewManager(),
		Trust:  trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = relay.Offer(ctx, relayURL, daemonID, func(ticket, _ string) {
			go func(ticket string) {
				c, binder, err := relay.AcceptE2E(context.Background(), relayURL, ticket, cert, peerPriv)
				if err != nil {
					return
				}
				srv.ServeConn(transport.Wrap(c, transport.Info{Transport: transport.KindRelay, TLS: true}), binder)
			}(ticket)
		})
	}()
	waitOffer(t, relayURL, daemonID)
	return relayFixture{relayURL: relayURL, key: clientPriv, peerPub: peerPub, daemonID: daemonID}
}

func (f relayFixture) endpoint() client.Endpoint {
	return client.Endpoint{
		Kind:       transport.KindRelay,
		RelayURL:   f.relayURL,
		RelayURLs:  []string{f.relayURL},
		PeerID:     f.daemonID,
		PeerPublic: f.peerPub,
	}
}

// A session through a relay that reads everything must reach the peer and come
// back, while the relay learns nothing about its content.
func TestRelayCannotReadSessionBytes(t *testing.T) {
	hostile := startHostileRelay(t, spliceRecord)
	fx := startFixture(t, "e2e-confidential", hostile.url)
	ep := fx.endpoint()

	info, err := client.Create(ep, fx.key, client.CreateOpts{})
	if err != nil {
		t.Fatalf("create through a recording relay: %v", err)
	}

	const marker = "SECRET123-do-not-leak"
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	attachDone := make(chan error, 1)
	// Attach, not Watch: Watch is read-only and would drop the keystrokes, so
	// the marker would never reach the shell and the test would prove nothing.
	go func() { attachDone <- client.Attach(ep, fx.key, info.ID, stdinR, stdoutW) }()

	if _, err := stdinW.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}

	// The shell echoes it, which proves these bytes really crossed the relay
	// rather than the assertions passing on an empty capture.
	echoed := make(chan bool, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stdoutR.Read(buf)
			if n > 0 && strings.Contains(string(buf[:n]), marker) {
				echoed <- true
				return
			}
			if err != nil {
				echoed <- false
				return
			}
		}
	}()
	select {
	case ok := <-echoed:
		if !ok {
			t.Fatal("the marker never came back, so nothing was proven")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the shell to echo the marker")
	}
	_ = stdinW.Close()

	up, down := hostile.saw("up"), hostile.saw("down")
	if len(up) == 0 || len(down) == 0 {
		t.Fatalf("the relay recorded nothing: %d up, %d down", len(up), len(down))
	}
	if strings.Contains(string(up), marker) || strings.Contains(string(down), marker) {
		t.Error("the relay saw the session content in cleartext")
	}
	// The server picks the session id, so learning it is the same failure one
	// step earlier.
	if strings.Contains(string(up), info.ID) || strings.Contains(string(down), info.ID) {
		t.Error("the relay saw the session id in cleartext")
	}
	_ = client.CloseSession(ep, fx.key, info.ID)
	select {
	case <-attachDone:
	case <-time.After(5 * time.Second):
	}
}

// Altering the stream must break the session rather than have the relay's
// version accepted.
func TestRelayTamperingBreaksTheSession(t *testing.T) {
	hostile := startHostileRelay(t, spliceTamper)
	fx := startFixture(t, "e2e-tamper", hostile.url)
	ep := fx.endpoint()

	// The relay may get its bite in during the handshake, so a refused dial is
	// already the property under test.
	c, err := client.Dial(ep, fx.key)
	if err != nil {
		t.Logf("dial refused after tampering: %v", err)
		return
	}
	defer func() { _ = c.Close() }()
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo alive\n")}); err != nil {
		t.Logf("send refused after tampering: %v", err)
		return
	}

	// Reading must fail: a corrupted record is never silently accepted.
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Recv(); err != nil {
			return
		}
	}
	t.Error("the session kept working after the relay altered a byte")
}

// Bytes the relay injects must not become session input.
func TestRelayInjectedBytesAreRejected(t *testing.T) {
	hostile := startHostileRelay(t, spliceInject)
	fx := startFixture(t, "e2e-inject", hostile.url)
	ep := fx.endpoint()

	// Injection lands in the first server-to-client record, which is the
	// ServerHello, so the handshake itself is expected to fail.
	c, err := client.Dial(ep, fx.key)
	if err != nil {
		t.Logf("dial refused after injection: %v", err)
		return
	}
	defer func() { _ = c.Close() }()
	if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: []byte("echo still-here\n")}); err != nil {
		t.Logf("send refused after injection: %v", err)
		return
	}

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		f, err := c.Recv()
		if err != nil {
			return // dropped: the injected bytes never became session input
		}
		if strings.Contains(string(f.Data), "injected") {
			t.Fatal("an injected frame was executed as session input")
		}
		if strings.Contains(string(f.Data), "still-here") {
			return // the injected bytes failed their record; the session is fine
		}
	}
}

// The attack the channel binding exists for: the relay terminates TLS on both
// legs and forwards plaintext. The client must refuse it.
func TestRelayReTerminatingTLSIsRejected(t *testing.T) {
	hostile := startHostileRelay(t, spliceMITM)
	fx := startFixture(t, "e2e-mitm", hostile.url)
	ep := fx.endpoint()

	_, err := client.Create(ep, fx.key, client.CreateOpts{})
	if err == nil {
		t.Fatal("the client accepted a relay that re-terminated TLS")
	}
	if !strings.Contains(err.Error(), "binding") && !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected a channel binding failure, got: %v", err)
	}
}

// An older peer that starts the session in cleartext must be refused with a
// message that says why, not an opaque handshake error.
func TestPlaintextPeerIsRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, err = transport.ServerE2E(conn, nil)
		errc <- err
	}()

	attacker, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attacker.Close() }()
	_, _ = attacker.Write([]byte(`{"type":"auth","public_key":"","data":""}`))

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("a plaintext peer completed the handshake")
		}
		if !strings.Contains(err.Error(), "end-to-end") {
			t.Errorf("expected a refusal naming the requirement, got: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no answer to a plaintext peer")
	}
}
