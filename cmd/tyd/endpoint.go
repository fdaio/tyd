package main

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"tyd/internal/auth"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/recent"
	"tyd/internal/transport"
)

func endpoint(opts options) (client.Endpoint, string, error) {
	if opts.addr != "" {
		return client.Endpoint{
			Kind:     transport.KindTLS,
			Address:  opts.addr,
			CertPath: opts.cert,
		}, "", nil
	}
	peerID, useLocal, err := resolvePeerTarget(opts)
	if err != nil {
		return client.Endpoint{}, "", err
	}
	if useLocal || peerID == "" {
		return client.Endpoint{
			Kind:    transport.KindUnix,
			Address: opts.socket,
		}, "", nil
	}
	relays := relayURLs(opts)
	platform, err := platformFor(opts)
	if err != nil {
		return client.Endpoint{}, "", err
	}
	cli := cpclient.New(platform)
	ep, err := cli.GetEndpointFull(peerID)
	if err != nil {
		if len(relays) > 0 {
			return client.Endpoint{
				Kind:      transport.KindRelay,
				RelayURL:  relays[0],
				RelayURLs: relays,
				PeerID:    peerID,
			}, peerID, nil
		}
		return client.Endpoint{}, "", fmt.Errorf("peer %s endpoint: %w", peerID, err)
	}
	kind := transport.KindTLS
	if strings.EqualFold(ep.Transport, "quic") {
		kind = transport.KindQUIC
	}
	addrs := endpointDialOrder(ep)
	if len(addrs) == 0 {
		if len(relays) > 0 {
			return client.Endpoint{
				Kind:      transport.KindRelay,
				RelayURL:  relays[0],
				RelayURLs: relays,
				PeerID:    peerID,
			}, peerID, nil
		}
		return client.Endpoint{}, "", fmt.Errorf("peer %s endpoint: no dial candidates", peerID)
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    addrs[0],
		CertFP:     ep.CertFP,
		Candidates: addrs[1:],
		RelayURL:   firstOrEmpty(relays),
		RelayURLs:  relays,
		PeerID:     peerID,
	}, peerID, nil
}

func firstOrEmpty(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// relayURLs parses --relay into an ordered, de-duplicated list of endpoints.
// The flag accepts a comma-separated list so more than one rendezvous can be
// offered on and fallen back to; "off" (or an empty list) disables the relay.
func relayURLs(opts options) []string {
	raw := strings.TrimSpace(opts.relay)
	if raw == "" {
		raw = strings.TrimSpace(paths.DefaultRelay())
	}
	out := make([]string, 0, 1)
	seen := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		u := strings.TrimSpace(part)
		if u == "" || u == "off" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

// relayURL renders the relay list for display, or "off" when disabled.
func relayURL(opts options) string {
	relays := relayURLs(opts)
	if len(relays) == 0 {
		return "off"
	}
	return strings.Join(relays, ",")
}

func endpointDialOrder(ep *controlpanel.EndpointResponse) []string {
	if ep == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(a string) {
		a = strings.TrimSpace(a)
		if a == "" {
			return
		}
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	add(ep.Addr)
	for _, c := range ep.Candidates {
		add(c)
	}
	return transport.PreferNonLoopback(out)
}

func resolvePeerTarget(opts options) (peerID string, useLocal bool, err error) {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return "", false, err
	}
	if opts.peer != "" {
		p, err := doc.Find(opts.peer)
		if err != nil {
			return "", false, err
		}
		return p.ID, false, nil
	}
	outbound := doc.Outbound()
	rec, _ := recent.Load(opts.recent)
	if rec != nil && rec.PeerID != "" {
		if p, err := doc.Find(rec.PeerID); err == nil {
			return p.ID, false, nil
		}
	}
	switch len(outbound) {
	case 0:
		return "", true, nil
	case 1:
		return outbound[0].ID, false, nil
	default:
		return "", false, fmt.Errorf("multiple peers; specify --peer <id|nickname>")
	}
}

func platformFor(opts options) (string, error) {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return "", err
	}
	if doc.Platform != "" {
		return doc.Platform, nil
	}
	return opts.platform, nil
}

func bindSessionProgress(ep *client.Endpoint, st *connectStatus) {
	if ep == nil {
		return
	}
	kind := string(ep.Kind)
	if kind == "" {
		kind = "unix"
	}
	ep.OnDial = func(addr string) {
		st.Log(dialDebugMsg(kind, addr))
	}
	ep.OnObserved = observedLogger(st.Log)
	ep.OnAttach = func() {
		st.Log("Connection established.")
		st.Log("Attaching session over " + kind + ".")
	}
	ep.OnReady = func() {
		st.Log("Attached.")
	}
	ep.OnLeave = func(msg string) {
		switch msg {
		case "interrupted":
			st.Leave("Interrupted.")
		case "session ended":
			st.Leave("Session ended.")
		default:
			st.Leave("Detaching.")
		}
	}
	ep.OnInputIgnored = nil
}

func bindWatchProgress(ep *client.Endpoint, st *connectStatus) {
	if ep == nil {
		return
	}
	kind := string(ep.Kind)
	if kind == "" {
		kind = "unix"
	}
	ep.OnDial = func(addr string) {
		st.Log(dialDebugMsg(kind, addr))
	}
	ep.OnObserved = observedLogger(st.Log)
	ep.OnAttach = func() {
		st.Log("Connection established.")
		st.Log("Starting watch over " + kind + ".")
	}
	ep.OnReady = func() {
		st.Log("Watching.")
		st.Notice("watching (read-only) — typing ignored; Ctrl-C / Ctrl-\\ stops")
	}
	ep.OnLeave = func(msg string) {
		switch msg {
		case "interrupted":
			st.Leave("Interrupted.")
		case "session ended":
			st.Leave("Session ended.")
		default:
			st.Leave("Stopped watching.")
		}
	}
	ep.OnInputIgnored = func() {
		st.Notice("watch is read-only — use: tyd session attach")
	}
}

// relayEndpoint builds the dual-NAT fallback endpoint for a peer.
func relayEndpoint(opts options, relays []string, peerID string) client.Endpoint {
	return client.Endpoint{
		Kind:       transport.KindRelay,
		RelayURL:   firstOrEmpty(relays),
		RelayURLs:  relays,
		PeerID:     peerID,
		PeerPublic: peerPublicKey(opts, peerID),
	}
}

// peerPublicKey is the pinned Ed25519 public key of a paired peer.
//
// The relay path has no certificate fingerprint to pin: the Control Panel's
// peer record carries no daemon id, and a relay-only daemon never publishes an
// endpoint. The peer's identity comes from pairing and is already the anchor
// for every other peer, so the inner TLS session is bound to it instead.
func peerPublicKey(opts options, idOrNick string) ed25519.PublicKey {
	idOrNick = strings.TrimSpace(idOrNick)
	if idOrNick == "" {
		return nil
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return nil
	}
	p, err := doc.Find(idOrNick)
	if err != nil {
		return nil
	}
	pub, err := auth.DecodePublic(p.PublicKey)
	if err != nil {
		return nil
	}
	return pub
}

func endpointFromRecord(rec catalog.Record) (client.Endpoint, bool) {
	if rec.Addr == "" {
		return client.Endpoint{}, false
	}
	kind := transport.KindTLS
	if strings.EqualFold(rec.Transport, "quic") {
		kind = transport.KindQUIC
	} else if strings.EqualFold(rec.Transport, "unix") || rec.CertFP == "" {
		kind = transport.KindUnix
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    rec.Addr,
		CertFP:     rec.CertFP,
		Candidates: append([]string(nil), rec.Candidates...),
		PeerID:     rec.PeerID,
	}, true
}

func endpointForSession(opts options, sessionID string) (client.Endpoint, string, bool, error) {
	cat := loadLocalCatalog(opts)
	if rec, ok := cat.Get(sessionID); ok {
		if ep, ok := endpointFromRecord(rec); ok {
			relays := relayURLs(opts)
			ep.RelayURL = firstOrEmpty(relays)
			ep.RelayURLs = relays
			if ep.PeerID == "" {
				ep.PeerID = rec.PeerID
			}
			ep.PeerPublic = peerPublicKey(opts, rec.PeerID)
			return ep, rec.PeerID, true, nil
		}
		if rec.PeerID != "" && opts.peer == "" {
			opts.peer = rec.PeerID
		}
	}
	ep, peerID, err := endpoint(opts)
	return ep, peerID, false, err
}

func endpointFromCPPeer(opts options, peerID string) (client.Endpoint, error) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return client.Endpoint{}, fmt.Errorf("empty peer id")
	}
	relays := relayURLs(opts)
	platform, err := platformFor(opts)
	if err != nil {
		return client.Endpoint{}, err
	}
	cli := cpclient.New(platform)
	ep, err := cli.GetEndpointFull(peerID)
	if err != nil {
		if len(relays) > 0 {
			return relayEndpoint(opts, relays, peerID), nil
		}
		return client.Endpoint{}, fmt.Errorf("peer %s endpoint: %w", peerID, err)
	}
	kind := transport.KindTLS
	if strings.EqualFold(ep.Transport, "quic") {
		kind = transport.KindQUIC
	}
	addrs := endpointDialOrder(ep)
	if len(addrs) == 0 {
		if len(relays) > 0 {
			return relayEndpoint(opts, relays, peerID), nil
		}
		return client.Endpoint{}, fmt.Errorf("peer %s endpoint: no dial candidates", peerID)
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    addrs[0],
		CertFP:     ep.CertFP,
		Candidates: addrs[1:],
		RelayURL:   firstOrEmpty(relays),
		RelayURLs:  relays,
		PeerID:     peerID,
	}, nil
}

func updateCatalogEndpoint(opts options, sessionID, peerID string, ep client.Endpoint) {
	if sessionID == "" || ep.Address == "" {
		return
	}
	rec := catalog.Record{
		ID:         sessionID,
		PeerID:     peerID,
		Addr:       ep.Address,
		CertFP:     ep.CertFP,
		Transport:  string(ep.Kind),
		Candidates: append([]string(nil), ep.Candidates...),
	}
	if cur, ok := loadLocalCatalog(opts).Get(sessionID); ok {
		rec.State = cur.State
		rec.CreatedAt = cur.CreatedAt
		if rec.PeerID == "" {
			rec.PeerID = cur.PeerID
		}
	}
	rememberSession(opts, rec)
}

// withEndpointRetry runs op; if it fails on a catalog-cached dial and peerID is
// set, refreshes the endpoint from CP, updates the catalog, and retries once.
func withEndpointRetry(opts options, st *connectStatus, sessionID, peerID string, ep client.Endpoint, fromCatalog bool, op func(client.Endpoint) error) error {
	bindSessionProgress(&ep, st)
	err := op(ep)
	if err == nil || !fromCatalog || peerID == "" || !client.IsRetryableDial(err) {
		return err
	}
	st.Log("Cached endpoint unreachable; refreshing from Control Panel.")
	fresh, rerr := endpointFromCPPeer(opts, peerID)
	if rerr != nil {
		return fmt.Errorf("%w\n(also failed to refresh endpoint: %v)", err, rerr)
	}
	updateCatalogEndpoint(opts, sessionID, peerID, fresh)
	if peerID != "" {
		st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), fresh.Kind))
	}
	bindSessionProgress(&fresh, st)
	return op(fresh)
}
