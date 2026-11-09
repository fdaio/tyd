package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/endpointcache"
	"tyd/internal/peers"
)

func signedRecord(t *testing.T, peerID string, priv ed25519.PrivateKey, addr string, published time.Time, ttl time.Duration, seq uint64) (auth.EndpointRecord, []byte) {
	t.Helper()
	rec := auth.NewEndpointRecord(peerID, auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
		addr, "aabbccdd", "quic", []string{addr}, published, ttl, seq)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec, sig
}

func signedEndpointResponse(t *testing.T, peerID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, addr string, seq uint64) *controlpanel.EndpointResponse {
	t.Helper()
	rec, sig := signedRecord(t, peerID, priv, addr, time.Now(), 90*time.Second, seq)
	return &controlpanel.EndpointResponse{
		DaemonID:   peerID,
		PublicKey:  auth.EncodePublic(pub),
		Addr:       rec.Addr,
		CertFP:     rec.CertFP,
		Transport:  "quic",
		Candidates: rec.Candidates,
		ExpiresAt:  rec.ExpiresAt,
		Proof:      &controlpanel.EndpointProof{Record: rec, Sig: auth.EncodeBytes(sig)},
	}
}

func storeCachedRecord(t *testing.T, opts options, rec auth.EndpointRecord, sig []byte, pub ed25519.PublicKey) {
	t.Helper()
	if err := endpointcache.Store(endpointCachePath(opts), endpointcache.Entry{
		PeerID: rec.DaemonID,
		Record: rec,
		Sig:    auth.EncodeBytes(sig),
	}, pub); err != nil {
		t.Fatal(err)
	}
}

// A verified endpoint already on disk is the whole point: the dial must not
// wait for the Control Panel, and must not ask it at all.
func TestCachedEndpointIsUsedWithoutTheControlPanel(t *testing.T) {
	pub, priv := keyPair(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	opts := pinnedOpts(t, srv.URL, "daemon-1", pub)
	opts.relay = "off"
	rec, sig := signedRecord(t, "daemon-1", priv, "203.0.113.7:41234", time.Now(), 90*time.Second, 1)
	storeCachedRecord(t, opts, rec, sig, pub)

	ep, peerID, fromCache, err := endpointForDial(opts)
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("Control Panel was contacted %d times", hits.Load())
	}
	if !fromCache || peerID != "daemon-1" {
		t.Fatalf("fromCache=%v peer=%q", fromCache, peerID)
	}
	if ep.Address != "203.0.113.7:41234" || ep.CertFP != "aabbccdd" {
		t.Fatalf("dialled %q fp %q", ep.Address, ep.CertFP)
	}
}

// The signed record outlives its TTL on this machine only as long as the
// Control Panel is unreachable; its signature still makes the address the
// peer's own word.
func TestExpiredCachedEndpointIsUsedWhenControlPanelIsDown(t *testing.T) {
	pub, priv := keyPair(t)
	opts := pinnedOpts(t, "http://127.0.0.1:1", "daemon-1", pub)
	opts.relay = "off"
	rec, sig := signedRecord(t, "daemon-1", priv, "203.0.113.7:41234", time.Now().Add(-10*time.Minute), time.Minute, 1)
	storeCachedRecord(t, opts, rec, sig, pub)

	var ep client.Endpoint
	var fromCache bool
	var err error
	stderr := captureStderr(t, func() {
		ep, _, fromCache, err = endpointForDial(opts)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache || ep.Address != "203.0.113.7:41234" {
		t.Fatalf("fromCache=%v addr=%q", fromCache, ep.Address)
	}
	if !strings.Contains(stderr, "expired cached endpoint") {
		t.Fatalf("no warning about the expired record: %q", stderr)
	}
}

// A cached address that no longer answers is refreshed from a live Control
// Panel, and the new record replaces the old one.
func TestDeadCachedEndpointRefreshesFromControlPanel(t *testing.T) {
	pub, priv := keyPair(t)
	opts := pinnedOpts(t, "", "daemon-1", pub)
	opts.relay = "off"
	stale, sig := signedRecord(t, "daemon-1", priv, "203.0.113.7:41234", time.Now(), 90*time.Second, 1)
	storeCachedRecord(t, opts, stale, sig, pub)
	opts.platform = serveEndpoint(t, signedEndpointResponse(t, "daemon-1", pub, priv, "198.51.100.9:443", 2))

	ep, _, fromCache, err := endpointForDial(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache || ep.Address != "203.0.113.7:41234" {
		t.Fatalf("expected the cached endpoint first, got fromCache=%v addr=%q", fromCache, ep.Address)
	}

	logFile, err := os.CreateTemp(t.TempDir(), "verbose.log")
	if err != nil {
		t.Fatal(err)
	}
	st := newConnectStatus(logFile, true)
	fresh, err := withEndpointRetry(opts, st, "", "daemon-1", ep, fromCache, isCreateDialError, func(ep client.Endpoint) error {
		switch ep.Address {
		case "203.0.113.7:41234":
			return fmt.Errorf("dial tcp 203.0.113.7:41234: connect: connection refused")
		case "198.51.100.9:443":
			return nil
		default:
			return fmt.Errorf("unexpected address %s", ep.Address)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Address != "198.51.100.9:443" {
		t.Fatalf("refreshed to %q", fresh.Address)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "refreshing from Control Panel") {
		t.Fatalf("refresh was not logged:\n%s", logged)
	}

	f, err := endpointcache.Load(endpointCachePath(opts))
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := f.Lookup("daemon-1")
	if !ok || entry.Record.Addr != "198.51.100.9:443" {
		t.Fatalf("cache not refreshed: %+v", entry)
	}
}

// A cache entry that fails verification is ignored, and the Control Panel is
// asked as if there were no cache at all.
func TestTamperedCacheIsIgnoredByResolution(t *testing.T) {
	pub, priv := keyPair(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signedEndpointResponse(t, "daemon-1", pub, priv, "198.51.100.9:443", 1))
	}))
	t.Cleanup(srv.Close)

	opts := pinnedOpts(t, srv.URL, "daemon-1", pub)
	opts.relay = "off"
	rec, sig := signedRecord(t, "daemon-1", priv, "203.0.113.7:41234", time.Now(), 90*time.Second, 1)
	storeCachedRecord(t, opts, rec, sig, pub)

	f, err := endpointcache.Load(endpointCachePath(opts))
	if err != nil {
		t.Fatal(err)
	}
	f.Peers[0].Record.Addr = "192.0.2.66:9"
	if err := endpointcache.Save(endpointCachePath(opts), f); err != nil {
		t.Fatal(err)
	}

	ep, _, fromCache, err := endpointForDial(opts)
	if err != nil {
		t.Fatal(err)
	}
	if fromCache {
		t.Fatal("a tampered cache entry was used")
	}
	if hits.Load() != 1 {
		t.Fatalf("Control Panel hits=%d, want 1", hits.Load())
	}
	if ep.Address != "198.51.100.9:443" {
		t.Fatalf("dialled %q", ep.Address)
	}
}

// With no cache and an unreachable Control Panel, the dial fails with the
// Control Panel's reason inside the interactive budget.
func TestNoCacheUnreachableControlPanelFailsWithinBudget(t *testing.T) {
	pub, _ := keyPair(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })

	opts := pinnedOpts(t, srv.URL, "daemon-1", pub)
	opts.relay = "off"

	start := time.Now()
	_, _, _, err := endpointForDial(opts)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a dial with no endpoint and no Control Panel succeeded")
	}
	if !strings.Contains(err.Error(), "Control Panel") {
		t.Fatalf("error does not name the Control Panel: %v", err)
	}
	if elapsed < dialControlPanelTimeout-time.Second {
		t.Fatalf("returned in %v, before the Control Panel budget", elapsed)
	}
	if elapsed > dialControlPanelTimeout+time.Second {
		t.Fatalf("took %v, longer than the Control Panel budget plus slack", elapsed)
	}
	if _, statErr := os.Stat(endpointCachePath(opts)); statErr == nil {
		t.Fatal("a failed lookup wrote a cache entry")
	}
}

// paired.json remembers the highest sequence already accepted. A cached record
// below it is a replay and must not be dialled, even though its signature is
// genuine.
func TestReplayedCachedEndpointIsIgnored(t *testing.T) {
	pub, priv := keyPair(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signedEndpointResponse(t, "daemon-1", pub, priv, "198.51.100.9:443", 3))
	}))
	t.Cleanup(srv.Close)

	opts := pinnedOpts(t, srv.URL, "daemon-1", pub)
	opts.relay = "off"
	rec, sig := signedRecord(t, "daemon-1", priv, "203.0.113.7:41234", time.Now(), 90*time.Second, 1)
	storeCachedRecord(t, opts, rec, sig, pub)

	paired, err := peers.LoadPaired(opts.paired)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := paired.Find("daemon-1")
	if err != nil {
		t.Fatal(err)
	}
	entry.EndpointSeq = 2
	paired.Upsert(entry)
	if err := peers.SavePaired(opts.paired, paired); err != nil {
		t.Fatal(err)
	}

	ep, _, fromCache, err := endpointForDial(opts)
	if err != nil {
		t.Fatal(err)
	}
	if fromCache {
		t.Fatal("a replayed cache entry was used")
	}
	if hits.Load() != 1 || ep.Address != "198.51.100.9:443" {
		t.Fatalf("hits=%d addr=%q", hits.Load(), ep.Address)
	}
}
