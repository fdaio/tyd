package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
	"tyd/internal/relay"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

func runUp(opts options) error {
	if _, err := ensureIdentity(opts); err != nil {
		return err
	}
	trust, err := auth.LoadStore(opts.trust)
	if err != nil {
		return fmt.Errorf("load trust %s: %w", opts.trust, err)
	}
	dataListen, err := resolveDataListen(opts)
	if err != nil {
		return err
	}
	state := loadPeerState(opts)
	approvalMode := controlpanel.DefaultApproval
	if mode, err := controlpanel.NormalizeApproval(state.ApprovalMode("")); err == nil {
		approvalMode = mode
	}
	mgr := session.NewManager()
	liveRoot := opts.live
	if liveRoot == "" {
		liveRoot = paths.DefaultLive()
	}
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable path: %w", err)
	}
	mgr.ConfigureLive(liveRoot, execPath)
	mgr.SetOutputLogMax(opts.outputLogMax)
	mgr.SetSendTimeout(opts.sessionSendTimeout)
	// Fail now rather than on the first create: a socket path that is too
	// long only shows up later as connect: invalid argument.
	if err := mgr.CheckSockPathFor(); err != nil {
		return err
	}
	restored, err := mgr.RestoreLive()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tyd live restore: %v\n", err)
	}
	for _, r := range restored {
		if r.OwnerPub == "" {
			continue
		}
		pub, err := auth.DecodePublic(r.OwnerPub)
		if err != nil {
			continue
		}
		_ = trust.EnsurePeer(r.Session.Owner, pub, nil)
		if err := trust.Grant(pub, r.Session.ID, auth.OwnerCaps...); err != nil {
			fmt.Fprintf(os.Stderr, "tyd restore caps %s: %v\n", r.Session.ID, err)
		}
	}
	if n := len(restored); n > 0 {
		fmt.Fprintf(os.Stderr, "tyd restored %d live session(s)\n", n)
	}
	var auditSink audit.Sink
	if opts.auditLog != "" {
		af, err := audit.OpenFile(opts.auditLog)
		if err != nil {
			return fmt.Errorf("audit log %s: %w", opts.auditLog, err)
		}
		defer af.Close()
		auditSink = af
	}
	srv := server.NewWithConfig(server.Config{
		Socket:             opts.socket,
		Listen:             opts.listen,
		DataListen:         dataListen,
		CertPath:           opts.cert,
		KeyPath:            opts.key,
		Mgr:                mgr,
		Trust:              trust,
		ApprovalMode:       approvalMode,
		Audit:              auditSink,
		SessionIdleTimeout: opts.sessionIdle,
	})
	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd listening unix %s\n", opts.socket)
	if approvalMode != controlpanel.ApprovalFull {
		if approvalMode == controlpanel.ApprovalFull {
			fmt.Fprintln(os.Stderr, "tyd approval mode full: remote peers are NOT asked before attaching or watching.")
			fmt.Fprintln(os.Stderr, "tyd   This is the default for a fresh install; use --approval pre to review each request.")
		} else {
			fmt.Fprintf(os.Stderr, "tyd approval mode %s\n", approvalMode)
		}
	}
	if opts.auditLog != "" {
		fmt.Fprintf(os.Stderr, "tyd audit log %s\n", opts.auditLog)
	}
	if opts.sessionIdle > 0 {
		fmt.Fprintf(os.Stderr, "tyd session idle timeout %s\n", opts.sessionIdle)
	}
	if opts.listen != "" && opts.listen != "off" {
		fmt.Fprintf(os.Stderr, "tyd listening tls  %s (cert fp %s)\n", srv.ListenAddr(), srv.TLSFingerprint())
	} else {
		fmt.Fprintln(os.Stderr, "tyd tls listen off (use --listen HOST:PORT to enable)")
	}

	stop := make(chan struct{})
	// One poll for the life of the daemon: it owns the schedule, and the route
	// it settled on, so the first round and every round after it talk to the
	// Control Panel the same way.
	poll := &cpPoll{}
	if id, err := ensureCPRegistration(opts, state); err != nil {
		fmt.Fprintf(os.Stderr, "cp registration restore skipped: %v\n", err)
	} else if id != "" {
		fmt.Fprintf(os.Stderr, "tyd restored CP registration %s\n", id)
	}
	if srv.DataPlaneAddr() != "" {
		cands := transport.PreferNonLoopback(transport.ExpandCandidates(srv.DataPlaneAddr(), opts.advertise))
		if len(cands) == 0 {
			fmt.Fprintln(os.Stderr, "tyd data-plane: no dial candidates")
		} else {
			pubAddr := cands[0]
			fmt.Fprintf(os.Stderr, "tyd data-plane quic %s (%d candidates published to CP)\n", pubAddr, len(cands))
			ep := dataEndpoint{addr: pubAddr, certFP: srv.TLSFingerprintFull(), candidates: cands}
			if err := cpRound(poll, opts, state, trust, ep); err != nil {
				fmt.Fprintf(os.Stderr, "cp sync skipped: %v\n", err)
			}
			go dataPlaneMaintain(poll, opts, state, trust, ep, stop)
		}
	} else {
		if err := syncPeersFromCP(opts, state); err != nil {
			fmt.Fprintf(os.Stderr, "cp peer sync skipped: %v\n", err)
		}
	}
	go maintainRelay(opts, state, srv, stop)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(stop)
	return srv.Close()
}

// loadPeerState reads peers.json once into memory. An unreadable file is set
// aside and the registration is recovered from the CP, because the CP holds
// the same pairing data and the local file is only a cache. The daemon keeps
// running either way: local sessions never depended on this file.
func loadPeerState(opts options) *peerstate.State {
	state, err := peerstate.Load(opts.peers)
	if err == nil {
		return state
	}
	if os.IsNotExist(err) {
		return peerstate.New(opts.peers, nil)
	}
	fmt.Fprintf(os.Stderr, "peers file unreadable (%v)\n", err)
	quarantined, qerr := quarantineFile(opts.peers)
	if qerr != nil {
		fmt.Fprintf(os.Stderr, "could not set aside %s: %v\n", opts.peers, qerr)
	} else {
		fmt.Fprintf(os.Stderr, "moved damaged file to %s\n", quarantined)
	}
	state = peerstate.New(opts.peers, nil)
	if err := recoverRegistration(opts, state); err != nil {
		fmt.Fprintf(os.Stderr, "could not recover registration from CP: %v\n", err)
		fmt.Fprintln(os.Stderr, "running local-only; fix the disk then run: tyd doctor --fix")
		return state
	}
	return state
}

// quarantineFile renames path aside so evidence survives and the next write
// starts clean. It returns the new name.
func quarantineFile(path string) (string, error) {
	target := path + ".corrupt." + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(path, target); err != nil {
		return "", err
	}
	return target, nil
}

// recoverRegistration rebuilds registration and peers from the CP using this
// daemon's identity. It states no approval mode, so the CP keeps the recorded
// one and a pre/post daemon cannot be silently relaxed to full.
func recoverRegistration(opts options, state *peerstate.State) error {
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(opts.platform)
	reg, err := cli.RecoverRegistration(pub)
	if err != nil {
		return err
	}
	remote, listErr := cli.ListPeers(reg.ID, pub)
	writeErr := state.Update(func(doc *peers.File) {
		doc.Platform = cli.BaseURL
		doc.Registration = &peers.Registration{
			ID:           reg.ID,
			PublicKey:    pub,
			ApprovalMode: reg.ApprovalMode,
			URL:          reg.URL,
			RegisteredAt: time.Now().UTC(),
		}
		if listErr == nil {
			doc.ReplaceFromRemote(cpPeersToLocal(remote))
		}
	})
	fmt.Fprintf(os.Stderr, "recovered CP registration %s (approval %s, %d peers)\n",
		reg.ID, reg.ApprovalMode, len(remote))
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "peers file still not writable (%v); running from memory\n", writeErr)
	}
	return nil
}

func resolveDataListen(opts options) (string, error) {
	v := strings.TrimSpace(opts.dataListen)
	if v == "" {
		v = "auto"
	}
	switch strings.ToLower(v) {
	case "off", "none", "false":
		return "off", nil
	case "auto":
		doc, err := peers.Load(opts.peers)
		if err != nil {
			return "", err
		}
		if doc.HasRegistration() {
			return "0.0.0.0:0", nil
		}
		return "off", nil
	default:
		return v, nil
	}
}

func advertisedAddr(host, listenAddr string) string {
	host = strings.TrimSpace(host)
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	if host == "" {
		return listenAddr
	}
	return net.JoinHostPort(host, port)
}

// ensureCPRegistration makes sure the Control Panel still knows this daemon.
// peers.json is a cache of what the daemon holds in memory, so it can be ahead
// of the Control Panel: a restarted Control Panel has no registrations at all,
// and a daemon nobody can name is a daemon nobody can reach. Restore is
// idempotent and only restates what this identity already knows -- it is keyed
// by this daemon's own id and public key and cannot mint an identity -- so it
// is safe on every start and on every 404.
//
// It returns the id it restored, or "" when the Control Panel already knew the
// daemon or there is nothing to restore. The caller logs it: the same restore
// reads differently at startup and in the middle of a poll.
func ensureCPRegistration(opts options, state *peerstate.State) (string, error) {
	doc := state.Snapshot()
	if !doc.HasRegistration() {
		return "", nil
	}
	platform := state.Platform(opts.platform)
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return "", err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	if doc.Registration.PublicKey != "" && doc.Registration.PublicKey != pub {
		return "", fmt.Errorf("peers.json registration public key does not match identity")
	}
	cli := cpclient.New(platform)
	if _, err := cli.ListPeers(doc.Registration.ID, pub); err == nil {
		return "", nil
	} else if !cpNotFound(err) {
		return "", err
	}
	cpPeers := make([]controlpanel.Peer, 0, len(doc.Peers))
	for _, p := range doc.Peers {
		cpPeers = append(cpPeers, controlpanel.Peer{
			ID:        p.ID,
			PublicKey: p.PublicKey,
			Nickname:  p.Nickname,
			PairedAt:  p.PairedAt,
			Direction: p.Direction,
		})
	}
	resp, err := cli.Restore(controlpanel.RestoreRequest{
		ID:           doc.Registration.ID,
		PublicKey:    pub,
		ApprovalMode: doc.Registration.ApprovalMode,
		Peers:        cpPeers,
	})
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

func cpNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

// dataEndpoint is what this daemon publishes about its own data plane: the
// address and certificate fingerprint a client dials, and the candidates it
// tries in order. Grouping them keeps the maintenance round from growing a
// parameter per field, since the round, the publish and the repair all need the
// same three.
type dataEndpoint struct {
	addr, certFP string
	candidates   []string
}

// endpointRequest builds the signed record this daemon publishes. An empty id
// means there is no registration, so there is nothing to publish and no peer
// list to ask for.
func endpointRequest(opts options, state *peerstate.State, ep dataEndpoint) (string, controlpanel.PublishEndpointRequest, error) {
	reg, ok := state.Registration()
	if !ok {
		return "", controlpanel.PublishEndpointRequest{}, nil
	}
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return "", controlpanel.PublishEndpointRequest{}, err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	ttl := controlpanel.DefaultEndpointTTL

	// Sign what we are about to publish, so a Control Panel can carry the record
	// but not rewrite it. The expiry and the sequence are ours: a client acts on
	// the signed values, never on the ones the Control Panel reports alongside.
	seq := endpointSeqFor(opts)
	record := auth.NewEndpointRecord(reg.ID, pub, ep.addr, ep.certFP, "quic", ep.candidates, time.Now(), ttl, seq)
	sig, err := record.Sign(key)
	if err != nil {
		return "", controlpanel.PublishEndpointRequest{}, fmt.Errorf("endpoint proof: %w", err)
	}
	return reg.ID, controlpanel.PublishEndpointRequest{
		PublicKey:  pub,
		Addr:       ep.addr,
		CertFP:     ep.certFP,
		Transport:  "quic",
		Candidates: ep.candidates,
		TTLSeconds: int(ttl / time.Second),
		Proof: &controlpanel.EndpointProof{
			Record: record,
			Sig:    auth.EncodeBytes(sig),
		},
	}, nil
}

func publishDataEndpoint(opts options, state *peerstate.State, ep dataEndpoint) error {
	id, req, err := endpointRequest(opts, state, ep)
	if err != nil || id == "" {
		return err
	}
	return cpclient.New(state.Platform(opts.platform)).PublishEndpointFull(id, req)
}

// endpointSeqFile keeps the publish sequence next to the pairing record. It only
// has to survive a restart: a restarted daemon that reissued numbers a client
// had already seen would look like a replay.
func endpointSeqFile(opts options) string {
	if strings.TrimSpace(opts.paired) != "" {
		return opts.paired + ".endpoint-seq"
	}
	return filepath.Join(paths.DefaultDir(), "endpoint-seq")
}

func endpointSeqFor(opts options) uint64 {
	path := endpointSeqFile(opts)
	var last uint64
	if b, err := os.ReadFile(path); err == nil {
		last, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	next := auth.NextEndpointSeq(last, time.Now())
	if err := os.WriteFile(path, []byte(strconv.FormatUint(next, 10)), 0o600); err != nil {
		// A sequence that repeats would only matter if a client had already
		// rejected it, so this is worth a word but not worth dropping the
		// publish over.
		fmt.Fprintf(os.Stderr, "tyd endpoint: could not persist the publish sequence: %v\n", err)
	}
	return next
}

// cpSyncOnce is one round trip against the Control Panel: publish the endpoint
// and take the peer list in a single request, then apply both locally.
func cpSyncOnce(opts options, state *peerstate.State, trust *auth.Store, ep dataEndpoint) error {
	id, req, err := endpointRequest(opts, state, ep)
	if err != nil || id == "" {
		return err
	}
	if err := seedPaired(opts); err != nil {
		fmt.Fprintf(os.Stderr, "tyd trust: could not read the local pairing record: %v\n", err)
	}
	resp, err := cpclient.New(state.Platform(opts.platform)).Sync(id, req)
	if err == nil {
		err = state.Update(func(doc *peers.File) {
			doc.ReplaceFromRemote(cpPeersToLocal(resp.Peers))
		})
	}
	// Trust is rebuilt from the local pairing record, not from what the Control
	// Panel just handed back, and it is rebuilt whether or not that call
	// succeeded: a Control Panel that is down must not be able to delay a
	// revocation that a local `tyd revoke` already recorded.
	injectPeerTrust(opts, trust, state.Snapshot())
	return err
}

// cpSyncTwice is the same round against a Control Panel without a /sync route:
// the peer list and the endpoint as two requests. Kept because a daemon can
// outlive the Control Panel it was built for, and a self-hosted one is
// redeployed by hand while install.sh upgrades daemons on its own.
func cpSyncTwice(opts options, state *peerstate.State, trust *auth.Store, ep dataEndpoint) error {
	return errors.Join(
		syncPeersAndTrust(opts, state, trust),
		publishDataEndpoint(opts, state, ep),
	)
}

// cpRound is one round of Control Panel maintenance.
//
// A 404 out of the combined call means one of two things, and telling them
// apart is the whole job: an unknown registration means this Control Panel lost
// us, and the restore puts it back; a Control Panel that knows the daemon and
// still 404s has no /sync route, which means it is older than this daemon. The
// restore is what separates them, because it starts by asking for the peer list
// this daemon id already had.
func cpRound(poll *cpPoll, opts options, state *peerstate.State, trust *auth.Store, ep dataEndpoint) error {
	state.ReloadIfSane()
	if poll.legacy {
		return cpSyncTwice(opts, state, trust, ep)
	}
	err := cpSyncOnce(opts, state, trust, ep)
	if !cpNotFound(err) {
		return err
	}
	id, rerr := ensureCPRegistration(opts, state)
	if rerr != nil {
		return fmt.Errorf("cp re-register: %w (last sync: %v)", rerr, err)
	}
	if id == "" {
		poll.legacy = true
		fmt.Fprintln(os.Stderr, "tyd cp: this Control Panel has no /sync route; using the two-request path (redeploy the Control Panel to halve what the fleet asks of it)")
		return cpSyncTwice(opts, state, trust, ep)
	}
	fmt.Fprintf(os.Stderr, "tyd cp: the Control Panel had forgotten this daemon; restored registration %s\n", id)
	return cpSyncOnce(opts, state, trust, ep)
}

// cpBackoff is how long the daemon waits before the next round, indexed by
// consecutive failures. The first step is the healthy interval, because a single
// failure is usually one dropped connection and retrying on the normal cadence
// costs one request. The last step is the ceiling: a Control Panel that is down
// must not be dialled on a fixed timer forever, and the relay carries the
// traffic meanwhile, so there is nothing to gain by knocking.
var cpBackoff = [...]time.Duration{
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

// cpPoll is everything a daemon remembers about talking to its Control Panel:
// when to go back, and which route to take. It is kept apart from the clock so
// the ladder, the route and the recovery can be tested without waiting out an
// interval.
type cpPoll struct {
	fails  int
	legacy bool // the Control Panel has no /sync route; use the two requests
}

// next records a round's outcome and returns the wait before the next one,
// before jitter.
func (p *cpPoll) next(ok bool) time.Duration {
	if ok {
		p.fails = 0
		return cpBackoff[0]
	}
	i := p.fails
	p.fails++
	if i >= len(cpBackoff)-1 {
		return cpBackoff[len(cpBackoff)-1]
	}
	return cpBackoff[i]
}

// jitteredWait spreads a wait by ±20% around it. Daemons started together stay
// in phase without it and arrive at the Control Panel as one spike every
// interval, and the endpoints they publish expire on a shared TTL, so the
// fleet already has a synchronising clock and does not need a second one.
func jitteredWait(d time.Duration, frac float64) time.Duration {
	const spread = 0.2
	return time.Duration(float64(d) * (1 + spread*(2*frac-1)))
}

func dataPlaneMaintain(poll *cpPoll, opts options, state *peerstate.State, trust *auth.Store, ep dataEndpoint, stop <-chan struct{}) {
	warned := false
	timer := time.NewTimer(jitteredWait(cpBackoff[0], rand.Float64()))
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		roundErr := cpRound(poll, opts, state, trust, ep)
		if roundErr != nil {
			fmt.Fprintf(os.Stderr, "cp maintenance: %v\n", roundErr)
		}
		// A full disk is not the Control Panel's fault, so it does not earn a
		// longer wait: the peers and endpoint above still need to move.
		if err := state.Flush(); err != nil {
			if !warned {
				fmt.Fprintf(os.Stderr, "peers file not writable (%v); running from memory and retrying\n", err)
				warned = true
			}
		} else if warned {
			fmt.Fprintln(os.Stderr, "peers file writable again")
			warned = false
		}
		timer.Reset(jitteredWait(poll.next(roundErr == nil), rand.Float64()))
	}
}

// acceptRelayE2E puts end-to-end TLS on a freshly spliced relay leg.
//
// The relay is a blind splice, so the application protocol used to run over it
// in cleartext: the relay and Cloudflare in front of it could read every
// keystroke and inject bytes into the shell. Both peers now wrap their own leg
// in TLS, and the server proves its identity by signing the TLS exporter with
// the daemon's Ed25519 key, so the client is not talking to a relay that
// re-terminated TLS in the middle.
func acceptRelayE2E(opts options, relayURL, ticket string) (net.Conn, []byte, error) {
	cert, err := transport.EnsureServerCert(opts.cert, opts.key)
	if err != nil {
		return nil, nil, fmt.Errorf("relay e2e certificate: %w", err)
	}
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return nil, nil, fmt.Errorf("relay e2e identity: %w", err)
	}
	return relay.AcceptE2E(context.Background(), relayURL, ticket, cert, key)
}

// maintainRelay keeps an outbound offer on every configured rendezvous relay,
// keyed by the current daemon id. Registration can appear or change after up
// starts (tyd register / --force); we reload peers.json and re-offer so clients
// do not see "peer offline" for a live daemon.
//
// Each relay is maintained independently: one endpoint being unreachable does
// not disturb the others, so a server stays dialable through any survivor. The
// relays share no state -- an offer lives in the one process it registered with,
// and a ticket is only ever claimed on that same process.
func maintainRelay(opts options, state *peerstate.State, srv *server.Server, stop <-chan struct{}) {
	urls := relayURLs(opts)
	if len(urls) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			maintainRelayOne(opts, state, srv, stop, url)
		}(url)
	}
	wg.Wait()
}

func maintainRelayOne(opts options, state *peerstate.State, srv *server.Server, stop <-chan struct{}, url string) {
	var (
		offerCancel context.CancelFunc
		offeringID  string
	)
	stopOffer := func() {
		if offerCancel != nil {
			offerCancel()
			offerCancel = nil
		}
		offeringID = ""
	}
	defer stopOffer()

	startOffer := func(id string) {
		stopOffer()
		offeringID = id
		ctx, cancel := context.WithCancel(context.Background())
		offerCancel = cancel
		fmt.Fprintf(os.Stderr, "tyd relay offering %s via %s\n", id, url)
		go func(daemonID string, ctx context.Context) {
			_ = relay.Offer(ctx, url, daemonID, func(ticket, observed string) {
				if observed != "" {
					// Recorded, not dialled: the client may be behind a NAT
					// whose mapping we cannot verify from here, so acting on
					// this is the next step (Phase 4b), not this one.
					fmt.Fprintf(os.Stderr, "tyd relay client observed at %s via %s\n", observed, url)
				}
				go func(ticket string) {
					secure, binder, err := acceptRelayE2E(opts, url, ticket)
					if err != nil {
						fmt.Fprintf(os.Stderr, "tyd relay accept %s: %v\n", ticket[:8], err)
						return
					}
					srv.ServeConn(transport.Wrap(secure, transport.Info{
						Transport:  transport.KindRelay,
						RemoteAddr: "relay:" + ticket[:8],
						TLS:        true,
					}), binder)
				}(ticket)
			})
		}(id, ctx)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		state.ReloadIfSane()
		reg, ok := state.Registration()
		id := ""
		if ok {
			id = strings.TrimSpace(reg.ID)
		}
		switch {
		case id == "" && offeringID != "":
			fmt.Fprintln(os.Stderr, "tyd relay offer stopped (no registration)")
			stopOffer()
		case id != "" && id != offeringID:
			startOffer(id)
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

// injectPeerTrust rebuilds the trust set from paired.json, the local record,
// never from peers.json -- which is rebuilt from whatever the Control Panel
// returns. A peer the Control Panel starts listing therefore gains nothing: it
// has to bring a pairing record this host can check against the secret it
// minted at invite time. The Control Panel can still withdraw a peer, because
// that only ever removes access.
func injectPeerTrust(opts options, trust *auth.Store, doc *peers.File) {
	if trust == nil {
		return
	}
	paired, err := peers.LoadPaired(pairedPath(opts))
	if err != nil {
		// Without the local record there is nothing to trust, and silently
		// falling back to the Control Panel's view is the bug this replaces.
		fmt.Fprintf(os.Stderr, "tyd trust: pairing record unreadable (%v); no peer is trusted", err)
		trust.DropUnlistedPeers(nil)
		return
	}

	// Prune first: a peer the Control Panel no longer lists loses trust even
	// if its record is still on disk, so revoke keeps working.
	listed := make(map[string]bool, len(doc.Peers))
	for _, p := range doc.Peers {
		listed[p.ID] = true
	}
	if dropped := paired.KeepVerified(listed); dropped > 0 {
		if err := peers.SavePaired(pairedPath(opts), paired); err != nil {
			fmt.Fprintf(os.Stderr, "tyd trust: could not record revocations: %v\n", err)
		}
	}

	var keep []ed25519.PublicKey
	var legacy int
	for _, p := range paired.Peers {
		// Only inbound peers are granted session access, as before. An outbound
		// entry is the server this daemon dials; trusting it here would let it
		// dial back in, which is not something pairing should hand out.
		if p.Direction != "inbound" && p.Direction != "" {
			continue
		}
		pub, err := p.Key()
		if err != nil {
			continue
		}
		if !p.Verified() && !p.Legacy() {
			// A record that does not verify is not a weaker case, it is a
			// broken one. Trusting it would be the same mistake.
			continue
		}
		if p.Legacy() {
			legacy++
		}
		name := p.Nickname
		if name == "" {
			name = p.ID
		}
		trust.EnsurePeer(name, pub, auth.AllGlobal)
		keep = append(keep, pub)
	}
	trust.DropUnlistedPeers(keep)
	if legacy > 0 {
		fmt.Fprintf(os.Stderr, "tyd trust: %d peer(s) paired before pairing records; their trust still rests on the Control Panel\n", legacy)
	}
}

// pairedPath is the local pairing record, which lives next to peers.json so a
// redirected --peers keeps the two together.
func pairedPath(opts options) string {
	if strings.TrimSpace(opts.paired) != "" {
		return opts.paired
	}
	return pairedPathFor(opts.peers)
}

// seedPaired adopts the peers a daemon already had, once, so an upgrade does
// not cut anyone off. After this runs the file is the only source of trust.
func seedPaired(opts options) error {
	path := pairedPath(opts)
	paired, err := peers.LoadPaired(path)
	if err != nil {
		return err
	}
	if len(paired.Peers) > 0 {
		return nil
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	added := paired.SeedLegacy(doc)
	if added == 0 {
		return nil
	}
	if err := peers.SavePaired(path, paired); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd trust: adopted %d existing peer(s) as legacy; their trust still rests on the Control Panel\n", added)
	return nil
}

func syncPeersAndTrust(opts options, state *peerstate.State, trust *auth.Store) error {
	if err := seedPaired(opts); err != nil {
		fmt.Fprintf(os.Stderr, "tyd trust: could not read the local pairing record: %v\n", err)
	}
	err := syncPeersFromCP(opts, state)

	injectPeerTrust(opts, trust, state.Snapshot())
	return err
}

func syncPeersFromCP(opts options, state *peerstate.State) error {
	reg, ok := state.Registration()
	if !ok {
		return nil
	}
	platform := state.Platform(opts.platform)
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(platform)
	remote, err := cli.ListPeers(reg.ID, pub)
	if err != nil {
		return err
	}
	return state.Update(func(doc *peers.File) {
		doc.ReplaceFromRemote(cpPeersToLocal(remote))
	})
}

func cpPeersToLocal(list []controlpanel.Peer) []peers.Peer {
	out := make([]peers.Peer, 0, len(list))
	for _, p := range list {
		out = append(out, peers.Peer{
			ID:        p.ID,
			PublicKey: p.PublicKey,
			Nickname:  p.Nickname,
			Direction: p.Direction,
			PairedAt:  p.PairedAt,
		})
	}
	return out
}
