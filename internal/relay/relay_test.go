package relay_test

import (
	"context"
	"net"
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

func TestDialTarget(t *testing.T) {
	addr, useTLS, err := relay.DialTarget("https://relay.getfda.dev")
	if err != nil || !useTLS || addr != "relay.getfda.dev:443" {
		t.Fatalf("https: %q %v %v", addr, useTLS, err)
	}
	addr, useTLS, err = relay.DialTarget("http://127.0.0.1:9090")
	if err != nil || useTLS || addr != "127.0.0.1:9090" {
		t.Fatalf("http: %q %v %v", addr, useTLS, err)
	}
}

func TestRelayMsgRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.WriteMsg(c1, relay.Msg{Type: relay.TypeOK, Ticket: "abc"})
	}()
	msg, err := relay.ReadMsg(c2)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if msg.Type != relay.TypeOK || msg.Ticket != "abc" {
		t.Fatalf("%+v", msg)
	}
}

func TestRelaySplicesSessionCreate(t *testing.T) {
	lnAddr, closeFn, err := relay.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn() })
	relayURL := "http://" + lnAddr.String()

	dir := t.TempDir()
	pub, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(dir, "id")
	if err := auth.WriteIdentity(idPath, priv); err != nil {
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
	mgr := session.NewManager()
	srv := server.NewWithConfig(server.Config{
		Socket: filepath.Join(dir, "tyd.sock"),
		Mgr:    mgr,
		Trust:  trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	daemonID := "daemon-test-1"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = relay.Offer(ctx, relayURL, daemonID, func(ticket string) {
			go func(ticket string) {
				c, err := relay.Accept(context.Background(), relayURL, ticket)
				if err != nil {
					t.Errorf("accept: %v", err)
					return
				}
				srv.ServeConn(transport.Wrap(c, transport.Info{Transport: transport.KindRelay}))
			}(ticket)
		})
	}()

	// Wait until the server offer is registered.
	ready := false
	for i := 0; i < 50; i++ {
		probeCtx, cancelProbe := context.WithTimeout(context.Background(), 500*time.Millisecond)
		c, err := relay.Dial(probeCtx, relayURL, daemonID)
		cancelProbe()
		if err != nil {
			if strings.Contains(err.Error(), "peer offline") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// Other errors still mean the offer path is reachable enough to try Create.
			ready = true
			break
		}
		_ = c.Close()
		ready = true
		break
	}
	if !ready {
		t.Fatal("offer never registered")
	}

	key, err := auth.LoadIdentity(idPath)
	if err != nil {
		t.Fatal(err)
	}
	ep := client.Endpoint{
		Kind:     transport.KindRelay,
		RelayURL: relayURL,
		PeerID:   daemonID,
	}
	info, err := client.Create(ep, key, client.CreateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" {
		t.Fatal("empty session id")
	}
	if err := client.CloseSession(ep, key, info.ID); err != nil {
		t.Fatal(err)
	}
}
