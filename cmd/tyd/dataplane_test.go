package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
)

// A Control Panel restart throws away every registration, invite and published
// endpoint, because none of them were ever on disk. The daemon's own record
// survives in peers.json, so the next maintenance round restores it and
// republishes the endpoint by itself -- which is what stops one `docker compose
// up -d --build` on the Control Panel host from pushing the whole fleet onto
// the relay until somebody restarts `tyd up` on every machine by hand.
//
// These tests pin that recovery, and pin what it must not cost: a healthy round
// still spends exactly the two requests it always did.

// restartableCP serves a Control Panel whose in-memory state can be dropped
// without the URL moving, which is precisely what restarting its container
// does: a new process on the same address with nothing carried over.
type restartableCP struct {
	mu       sync.Mutex
	svc      *controlpanel.Service
	failWith int

	srv      *httptest.Server
	restores atomic.Int64
	requests atomic.Int64
}

// startRestartableCP serves a Control Panel whose in-memory state can be dropped
// without the URL moving, which is precisely what restarting its container
// does: a new process on the same address with nothing carried over.
//
// noSync drops the /sync route instead, which is what a Control Panel older
// than this daemon looks like: the daemon is known, every other route answers,
// and the one route it added answers 404.
func startRestartableCP(t *testing.T, noSync bool) *restartableCP {
	t.Helper()
	cp := &restartableCP{svc: controlpanel.New()}
	cp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if noSync && strings.HasSuffix(r.URL.Path, "/sync") {
			http.NotFound(w, r)
			return
		}
		cp.requests.Add(1)
		if r.URL.Path == "/v1/restore" {
			cp.restores.Add(1)
		}
		cp.mu.Lock()
		status, h := cp.failWith, cp.svc.Handler()
		cp.mu.Unlock()
		if status != 0 {
			http.Error(w, "control panel is unwell", status)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(cp.srv.Close)
	return cp
}

// restart drops all state, the way a restarted Control Panel container does.
func (c *restartableCP) restart() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.svc = controlpanel.New()
}

func (c *restartableCP) service() *controlpanel.Service {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.svc
}

// registeredDaemon writes the files a daemon that has already paired would
// have, and returns options pointing at platform.
func registeredDaemon(t *testing.T, platform, daemonID string, priv ed25519.PrivateKey) (options, *peerstate.State, *auth.Store) {
	t.Helper()
	dir := t.TempDir()
	opts := options{
		identity: filepath.Join(dir, "id_ed25519"),
		trust:    filepath.Join(dir, "trusted.json"),
		peers:    filepath.Join(dir, "peers.json"),
		paired:   filepath.Join(dir, "paired.json"),
		platform: platform,
	}
	if err := auth.WriteIdentity(opts.identity, priv); err != nil {
		t.Fatal(err)
	}
	if err := peers.SavePaired(opts.paired, &peers.PairedFile{}); err != nil {
		t.Fatal(err)
	}
	doc := &peers.File{
		Platform: platform,
		Registration: &peers.Registration{
			ID:           daemonID,
			PublicKey:    auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
			ApprovalMode: controlpanel.DefaultApproval,
			RegisteredAt: time.Now().UTC(),
		},
	}
	if err := peers.Save(opts.peers, doc); err != nil {
		t.Fatal(err)
	}
	state, err := peerstate.Load(opts.peers)
	if err != nil {
		t.Fatal(err)
	}
	return opts, state, auth.NewStore()
}

func TestCPRoundRepublishesAfterTheControlPanelForgetsTheDaemon(t *testing.T) {
	cp := startRestartableCP(t, false)
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	daemonID := "0123456789abcdef"
	opts, state, trust := registeredDaemon(t, cp.srv.URL, daemonID, priv)
	_, err = cp.service().Restore(controlpanel.RestoreRequest{
		ID:           daemonID,
		PublicKey:    auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
		ApprovalMode: controlpanel.DefaultApproval,
	})
	if err != nil {
		t.Fatal(err)
	}
	const addr, certFP, candidate = "198.51.100.7:41234", "aabbccdd", "203.0.113.9:41234"

	if err := cpRound(&cpPoll{}, opts, state, trust, dataEndpoint{addr: addr, certFP: certFP, candidates: []string{candidate}}); err != nil {
		t.Fatalf("a healthy round must not report an error: %v", err)
	}
	live := cpclient.New(cp.srv.URL).GetEndpointFull
	if _, err := live(daemonID); err != nil {
		t.Fatalf("the endpoint should be published after a healthy round: %v", err)
	}

	cp.restart()
	if _, err := live(daemonID); err == nil {
		t.Fatal("the restart should have forgotten the endpoint")
	}

	if err := cpRound(&cpPoll{}, opts, state, trust, dataEndpoint{addr: addr, certFP: certFP, candidates: []string{candidate}}); err != nil {
		t.Fatalf("the round after a Control Panel restart must heal itself: %v", err)
	}
	if cp.restores.Load() != 1 {
		t.Errorf("recovery should restore the registration once, got %d", cp.restores.Load())
	}
	ep, err := live(daemonID)
	if err != nil {
		t.Fatalf("the endpoint is what clients dial directly; it must come back in the healing round: %v", err)
	}
	if ep.Addr != addr || ep.CertFP != certFP {
		t.Errorf("republished endpoint is %s/%s, want %s/%s", ep.Addr, ep.CertFP, addr, certFP)
	}
	if len(ep.Candidates) != 1 || ep.Candidates[0] != candidate {
		t.Errorf("candidates did not survive the restart: %v", ep.Candidates)
	}
}

func TestCPRoundCostsOneRequestWhenHealthy(t *testing.T) {
	cp := startRestartableCP(t, false)
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	daemonID := "0123456789abcdef"
	opts, state, trust := registeredDaemon(t, cp.srv.URL, daemonID, priv)
	_, err = cp.service().Restore(controlpanel.RestoreRequest{
		ID:           daemonID,
		PublicKey:    auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
		ApprovalMode: controlpanel.DefaultApproval,
	})
	if err != nil {
		t.Fatal(err)
	}

	const addr, certFP = "198.51.100.7:41234", "aabbccdd"
	before := cp.requests.Load()
	if err := cpRound(&cpPoll{}, opts, state, trust, dataEndpoint{addr: addr, certFP: certFP, candidates: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	// One request, for the peer list and the endpoint together. A heal that ran
	// on every tick would show up here as a second.
	if spent := cp.requests.Load() - before; spent != 1 {
		t.Errorf("a healthy round spent %d requests, want 1", spent)
	}
	if n := cp.restores.Load(); n != 0 {
		t.Errorf("a Control Panel that knows the daemon must not be restored against, got %d restores", n)
	}
}

func TestCPRoundFallsBackWhenTheControlPanelHasNoSyncRoute(t *testing.T) {
	cp := startRestartableCP(t, true)
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	daemonID := "0123456789abcdef"
	opts, state, trust := registeredDaemon(t, cp.srv.URL, daemonID, priv)
	_, err = cp.service().Restore(controlpanel.RestoreRequest{
		ID:           daemonID,
		PublicKey:    auth.EncodePublic(priv.Public().(ed25519.PublicKey)),
		ApprovalMode: controlpanel.DefaultApproval,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A daemon is upgraded by install.sh on its own schedule, and a self-hosted
	// Control Panel is redeployed by hand, so a daemon outliving the Control
	// Panel it was built for is ordinary rather than exotic. Treating that 404
	// as a lost registration instead would leave the daemon republishing into a
	// 404 every round and never getting its endpoint back.
	const addr, certFP = "198.51.100.7:41234", "aabbccdd"
	ep := dataEndpoint{addr: addr, certFP: certFP, candidates: []string{addr}}
	poll := &cpPoll{}
	if err := cpRound(poll, opts, state, trust, ep); err != nil {
		t.Fatalf("a Control Panel without /sync must still be served: %v", err)
	}
	if !poll.legacy {
		t.Fatal("the round should have settled on the two-request path")
	}
	if n := cp.restores.Load(); n != 0 {
		t.Errorf("an older Control Panel has not lost the daemon, got %d restores", n)
	}
	if _, err := cpclient.New(cp.srv.URL).GetEndpointFull(daemonID); err != nil {
		t.Fatalf("the fallback must still publish the endpoint: %v", err)
	}

	// And it stays on that path rather than re-discovering it every round.
	before := cp.requests.Load()
	if err := cpRound(poll, opts, state, trust, ep); err != nil {
		t.Fatal(err)
	}
	if spent := cp.requests.Load() - before; spent != 2 {
		t.Errorf("the fallback spent %d requests, want 2", spent)
	}
}

func TestCPRoundDoesNotRestoreAgainstAnUnhealthyControlPanel(t *testing.T) {
	cp := startRestartableCP(t, false)
	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	daemonID := "0123456789abcdef"
	opts, state, trust := registeredDaemon(t, cp.srv.URL, daemonID, priv)
	cp.mu.Lock()
	cp.failWith = http.StatusInternalServerError
	cp.mu.Unlock()

	const addr, certFP = "198.51.100.7:41234", "aabbccdd"
	before := cp.requests.Load()
	if err := cpRound(&cpPoll{}, opts, state, trust, dataEndpoint{addr: addr, certFP: certFP, candidates: []string{addr}}); err == nil {
		t.Fatal("a Control Panel answering 500 should fail the round, not be papered over")
	}
	// Re-registering against a Control Panel that is up but unwell would answer
	// the same 500, so the round has to stop here and let the backoff decide
	// when to look again.
	if n := cp.restores.Load(); n != 0 {
		t.Errorf("restore was attempted %d times against an unhealthy Control Panel", n)
	}
	if spent := cp.requests.Load() - before; spent != 1 {
		t.Errorf("a failing round spent %d requests, want 1", spent)
	}
}

func TestCPPollBackoffLadder(t *testing.T) {
	p := &cpPoll{}
	if got := p.next(true); got != cpBackoff[0] {
		t.Errorf("a healthy round waits %v, want %v", got, cpBackoff[0])
	}
	// One dropped connection is not a Control Panel outage, so the first failure
	// retries on the normal cadence; after that the waits grow to a ceiling.
	for i, want := range cpBackoff {
		if got := p.next(false); got != want {
			t.Errorf("failure %d waits %v, want %v", i+1, got, want)
		}
	}
	if got := p.next(false); got != cpBackoff[len(cpBackoff)-1] {
		t.Errorf("a long outage must cap at %v, got %v", cpBackoff[len(cpBackoff)-1], got)
	}
	// Recovery drops straight back to the healthy interval, and the next
	// failure starts the ladder again rather than resuming where it left off.
	if got := p.next(true); got != cpBackoff[0] {
		t.Errorf("after recovery the wait is %v, want %v", got, cpBackoff[0])
	}
	if got := p.next(false); got != cpBackoff[0] {
		t.Errorf("the ladder must restart after a recovery, got %v", got)
	}
}

func TestJitteredWaitSpreadsTheInterval(t *testing.T) {
	const d = 30 * time.Second
	for _, tc := range []struct {
		frac float64
		want time.Duration
	}{
		{frac: 0, want: 24 * time.Second},
		{frac: 0.5, want: d},
	} {
		if got := jitteredWait(d, tc.frac); got != tc.want {
			t.Errorf("jitteredWait(%v, %v) = %v, want %v", d, tc.frac, got, tc.want)
		}
	}
	// Every daemon in a fleet draws from the same range, so a tight bound is
	// what actually keeps them from arriving together.
	lo, hi := time.Duration(0.8*float64(d)), time.Duration(1.2*float64(d))
	for _, frac := range []float64{0, 0.13, 0.5, 0.87, 0.999} {
		if got := jitteredWait(d, frac); got < lo || got > hi {
			t.Errorf("jitteredWait(%v, %v) = %v, outside [%v, %v]", d, frac, got, lo, hi)
		}
	}
}
