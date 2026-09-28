package relay_test

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"tyd/internal/relay"
	"tyd/internal/transport"
)

// The relay cross-announces the address it observes for each side of a call.
// Both sides are told, and neither dials it in this step: the value is a
// measurement, and whether it would actually connect is Phase 4b's question.

// startObservedRelay runs a relay and offers daemonID on it, returning the relay
// URL and a channel of the observed client addresses it announces.
func startObservedRelay(t *testing.T, daemonID string) (string, <-chan string) {
	t.Helper()
	lnAddr, closeFn, err := relay.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })
	relayURL := "http://" + lnAddr.String()

	observed := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = relay.Offer(ctx, relayURL, daemonID, func(ticket, obs string) {
			select {
			case observed <- obs:
			default:
			}
			go func() {
				// No real tyd server behind this: the accept leg only needs to
				// complete the handshake so the client receives its OK.
				if c, err := relay.Accept(context.Background(), relayURL, ticket); err == nil {
					_, _ = c.Write([]byte("x"))
					_ = c.Close()
				}
			}()
		})
	}()
	waitOffer(t, relayURL, daemonID)
	return relayURL, observed
}

// waitObserved reads one announcement, skipping the empty ones.
func waitObserved(t *testing.T, ch <-chan string) string {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case v := <-ch:
			if v != "" {
				return v
			}
		case <-deadline:
			t.Fatal("relay never announced an observed address")
		}
	}
}

func TestRelayAnnouncesObservedClientAddress(t *testing.T) {
	relayURL, observed := startObservedRelay(t, "daemon-observed-server")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := relay.DialDetailed(ctx, relayURL, "daemon-observed-server")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer res.Conn.Close()
	_, _ = transport.Wrap(res.Conn, transport.Info{Transport: transport.KindRelay}).Write(nil)

	// The server is told where the client actually is. Loopback here, but the
	// point is that it is the relay's RemoteAddr, not anything self-reported.
	got := waitObserved(t, observed)
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("observed %q is not host:port: %v", got, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("observed host = %q, want 127.0.0.1 (the relay's view, not a claim)", host)
	}
	if port == "" || port == "0" {
		t.Fatalf("observed port = %q, want a real port", port)
	}
}

func TestDialDetailedReportsObservedServerAddress(t *testing.T) {
	relayURL, _ := startObservedRelay(t, "daemon-observed-target")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := relay.DialDetailed(ctx, relayURL, "daemon-observed-target")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer res.Conn.Close()

	if res.Observed == "" {
		t.Fatal("client got no observed server address")
	}
	host, port, err := net.SplitHostPort(res.Observed)
	if err != nil {
		t.Fatalf("observed %q is not host:port: %v", res.Observed, err)
	}
	if host != "127.0.0.1" || port == "" {
		t.Fatalf("observed = %q, want a loopback host:port", res.Observed)
	}
}

// Dial keeps its old signature and must not lose the observation to a wrapper
// that discards it.
func TestDialStillSplices(t *testing.T) {
	relayURL, _ := startObservedRelay(t, "daemon-plain-dial")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := relay.Dial(ctx, relayURL, "daemon-plain-dial")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write after splice: %v", err)
	}
	buf := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("read after splice: %v", err)
	}
}

// An absent Observed field must be inert, not an error: that is what keeps a
// new daemon talking to an old relay and vice versa.
func TestObservedFieldIsOptional(t *testing.T) {
	old := relay.Msg{Type: relay.TypeIncoming, Ticket: "t1"}
	if old.Observed != "" {
		t.Fatal("zero Observed must be empty")
	}
	// A frame from a peer that never sets it still round-trips.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = relay.WriteMsg(c, old)
		time.Sleep(100 * time.Millisecond)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := relay.ReadMsg(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Ticket != "t1" || got.Observed != "" {
		t.Fatalf("round-trip = %+v, want ticket t1 and empty Observed", got)
	}
	// And the field must not be emitted when unset, so old relays see the exact
	// frame they saw before.
	raw, err := marshalMsg(relay.Msg{Type: relay.TypeOK, Ticket: "t2", Observed: ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "observed") {
		t.Fatalf("empty Observed serialized as %s, want it omitted", raw)
	}
	raw, err = marshalMsg(relay.Msg{Type: relay.TypeOK, Observed: "203.0.113.7:41234"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "203.0.113.7:41234") {
		t.Fatalf("Observed missing from %s", raw)
	}
}

func marshalMsg(m relay.Msg) ([]byte, error) { return json.Marshal(m) }
