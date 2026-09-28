package relay_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/relay"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// deadRelayURL returns a URL that refuses connections quickly, standing in for
// a relay process that is down.
func deadRelayURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

// startRelayOffer runs a relay and keeps an offer for daemonID on it, returning
// the relay URL and the server identity key directory.
func startRelayOffer(t *testing.T, daemonID string) (string, ed25519.PrivateKey) {
	t.Helper()
	lnAddr, closeFn, err := relay.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })
	relayURL := "http://" + lnAddr.String()

	// A short socket path: t.TempDir() embeds the (long) test name and blows
	// past the ~104-byte sun_path limit on macOS.
	dir, err := os.MkdirTemp("", "tydmr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pub, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := priv
	if err := auth.WriteIdentity(filepath.Join(dir, "id"), priv); err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(dir, "trust.json")
	if err := auth.WriteBootstrapTrust(trustPath, "local", pub); err != nil {
		t.Fatal(err)
	}
	trust, err := auth.LoadStore(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewWithConfig(server.Config{
		Socket: filepath.Join(dir, "tyd.sock"),
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
		_ = relay.Offer(ctx, relayURL, daemonID, func(ticket string) {
			go func(ticket string) {
				c, err := relay.Accept(context.Background(), relayURL, ticket)
				if err != nil {
					return
				}
				srv.ServeConn(transport.Wrap(c, transport.Info{Transport: transport.KindRelay}))
			}(ticket)
		})
	}()
	waitOffer(t, relayURL, daemonID)
	return relayURL, key
}

// waitOffer blocks until the daemon offer is registered on the relay.
func waitOffer(t *testing.T, relayURL, daemonID string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		probeCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		c, err := relay.Dial(probeCtx, relayURL, daemonID)
		cancel()
		if err == nil {
			_ = c.Close()
			return
		}
		if !strings.Contains(err.Error(), "peer offline") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("offer never registered")
}

// TestClientFallsBackToSecondRelay proves the client walks the relay list: the
// first entry is dead, the second is serving the offer, and the session is
// created through the survivor.
func TestClientFallsBackToSecondRelay(t *testing.T) {
	daemonID := "daemon-multi-b"
	alive, key := startRelayOffer(t, daemonID)
	dead := deadRelayURL(t)

	var tried []string
	ep := client.Endpoint{
		Kind:      transport.KindRelay,
		RelayURL:  alive,
		RelayURLs: []string{dead, alive},
		PeerID:    daemonID,
		OnDial:    func(a string) { tried = append(tried, a) },
	}
	info, err := client.Create(ep, key, client.CreateOpts{})
	if err != nil {
		t.Fatalf("create via second relay: %v", err)
	}
	if info.ID == "" {
		t.Fatal("empty session id")
	}
	if len(tried) == 0 || tried[0] != "relay "+dead {
		t.Fatalf("expected dead relay tried first, got %v", tried)
	}
}

// TestClientStopsAtFirstLiveRelay proves ordering: when the first entry already
// serves the offer, later entries are not dialled.
func TestClientStopsAtFirstLiveRelay(t *testing.T) {
	daemonID := "daemon-multi-a"
	first, key := startRelayOffer(t, daemonID)
	second, _ := startRelayOffer(t, daemonID)

	var tried []string
	ep := client.Endpoint{
		Kind:      transport.KindRelay,
		RelayURL:  first,
		RelayURLs: []string{first, second},
		PeerID:    daemonID,
		OnDial:    func(a string) { tried = append(tried, a) },
	}
	if _, err := client.Create(ep, key, client.CreateOpts{}); err != nil {
		t.Fatalf("create via first relay: %v", err)
	}
	if len(tried) != 1 || tried[0] != "relay "+first {
		t.Fatalf("expected only the first relay dialled, got %v", tried)
	}
}

// TestClientRelayListWithNoLiveRelay reports every attempt.
func TestClientRelayListWithNoLiveRelay(t *testing.T) {
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ep := client.Endpoint{
		Kind:      transport.KindRelay,
		RelayURLs: []string{deadRelayURL(t), deadRelayURL(t)},
		PeerID:    "nobody",
	}
	_, err = client.Create(ep, priv, client.CreateOpts{})
	if err == nil {
		t.Fatal("expected failure with no reachable relay")
	}
	if !strings.Contains(err.Error(), "tried:") {
		t.Fatalf("want aggregated attempt list, got %v", err)
	}
}
