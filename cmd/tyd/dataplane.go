package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"os/signal"
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
		fmt.Fprintf(os.Stderr, "tyd approval mode %s\n", approvalMode)
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
	if err := ensureCPRegistration(opts, state); err != nil {
		fmt.Fprintf(os.Stderr, "cp registration restore skipped: %v\n", err)
	}
	if srv.DataPlaneAddr() != "" {
		cands := transport.PreferNonLoopback(transport.ExpandCandidates(srv.DataPlaneAddr(), opts.advertise))
		if len(cands) == 0 {
			fmt.Fprintln(os.Stderr, "tyd data-plane: no dial candidates")
		} else {
			pubAddr := cands[0]
			fmt.Fprintf(os.Stderr, "tyd data-plane quic %s (%d candidates published to CP)\n", pubAddr, len(cands))
			if err := syncPeersAndTrust(opts, state, trust); err != nil {
				fmt.Fprintf(os.Stderr, "cp peer sync skipped: %v\n", err)
			}
			if err := publishDataEndpoint(opts, state, pubAddr, srv.TLSFingerprintFull(), cands); err != nil {
				fmt.Fprintf(os.Stderr, "cp endpoint publish skipped: %v\n", err)
			}
			go dataPlaneMaintain(opts, state, trust, pubAddr, srv.TLSFingerprintFull(), cands, stop)
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

func ensureCPRegistration(opts options, state *peerstate.State) error {
	doc := state.Snapshot()
	if !doc.HasRegistration() {
		return nil
	}
	platform := state.Platform(opts.platform)
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	if doc.Registration.PublicKey != "" && doc.Registration.PublicKey != pub {
		return fmt.Errorf("peers.json registration public key does not match identity")
	}
	cli := cpclient.New(platform)
	if _, err := cli.ListPeers(doc.Registration.ID, pub); err == nil {
		return nil
	} else if !cpNotFound(err) {
		return err
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
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd restored CP registration %s\n", resp.ID)
	return nil
}

func cpNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

func publishDataEndpoint(opts options, state *peerstate.State, addr, certFP string, candidates []string) error {
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
	ttlSec := int(controlpanel.DefaultEndpointTTL / time.Second)
	return cli.PublishEndpointFull(reg.ID, controlpanel.PublishEndpointRequest{
		PublicKey:  pub,
		Addr:       addr,
		CertFP:     certFP,
		Transport:  "quic",
		Candidates: candidates,
		TTLSeconds: ttlSec,
	})
}

func dataPlaneMaintain(opts options, state *peerstate.State, trust *auth.Store, addr, certFP string, candidates []string, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:

			state.ReloadIfSane()
			if err := syncPeersAndTrust(opts, state, trust); err != nil {
				fmt.Fprintf(os.Stderr, "cp peer sync: %v\n", err)
			}
			if err := publishDataEndpoint(opts, state, addr, certFP, candidates); err != nil {
				fmt.Fprintf(os.Stderr, "cp endpoint publish: %v\n", err)
			}
			if err := state.Flush(); err != nil {
				if !warned {
					fmt.Fprintf(os.Stderr, "peers file not writable (%v); running from memory and retrying\n", err)
					warned = true
				}
			} else if warned {
				fmt.Fprintln(os.Stderr, "peers file writable again")
				warned = false
			}
		}
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
