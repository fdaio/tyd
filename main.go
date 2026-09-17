package main

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"tyd/internal/alias"
	"tyd/internal/auth"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/recent"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

const (
	ansiCyan   = "\033[36m"
	ansiReset  = "\033[0m"
	helpColPad = 22
)

type helpRow struct {
	name string
	desc string
}

type options struct {
	socket     string
	listen     string
	dataListen string
	advertise  string
	addr       string
	peer       string
	identity   string
	trust      string
	peers      string
	recent     string
	aliases    string
	sessions   string
	platform   string
	approval   string
	as         string
	cert       string
	key        string
	noWait     bool
	detach     bool
	verbose    bool
	force      bool
	cmd        string
	rest       []string
}

func main() {
	repairTTY()
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		usage()
		os.Exit(2)
	}
	if opts.cmd == "" || opts.cmd == "help" || opts.cmd == "-h" || opts.cmd == "--help" {
		usage()
		return
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
	platform, err := platformFor(opts)
	if err != nil {
		return client.Endpoint{}, "", err
	}
	cli := cpclient.New(platform)
	ep, err := cli.GetEndpointFull(peerID)
	if err != nil {
		return client.Endpoint{}, "", fmt.Errorf("peer %s endpoint: %w", peerID, err)
	}
	kind := transport.KindTLS
	if strings.EqualFold(ep.Transport, "quic") {
		kind = transport.KindQUIC
	}
	addrs := endpointDialOrder(ep)
	if len(addrs) == 0 {
		return client.Endpoint{}, "", fmt.Errorf("peer %s endpoint: no dial candidates", peerID)
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    addrs[0],
		CertFP:     ep.CertFP,
		Candidates: addrs[1:],
	}, peerID, nil
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

func rememberPeerSession(opts options, peerID, sessionID string) {
	_ = recent.Remember(opts.recent, peerID, sessionID)
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
}

func sessionsPath(opts options) string {
	if opts.sessions != "" {
		return opts.sessions
	}
	return paths.DefaultSessions()
}

func loadLocalCatalog(opts options) *catalog.File {
	path := sessionsPath(opts)
	f, err := catalog.Load(path)
	if err != nil {
		f = &catalog.File{}
	}
	n := len(f.Sessions)
	adoc, _ := alias.Load(opts.aliases)
	f.MergeAliases(adoc)
	rec, _ := recent.Load(opts.recent)
	f.MergeRecent(rec)
	if f.BackfillCreated() {
		n = -1
	}
	if len(f.Sessions) > n {
		_ = catalog.Save(path, f)
	}
	return f
}

func rememberSession(opts options, rec catalog.Record) {
	_ = catalog.Remember(sessionsPath(opts), rec)
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
	}, true
}

func endpointForSession(opts options, sessionID string) (client.Endpoint, string, bool, error) {
	cat := loadLocalCatalog(opts)
	if rec, ok := cat.Get(sessionID); ok {
		if ep, ok := endpointFromRecord(rec); ok {
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
	platform, err := platformFor(opts)
	if err != nil {
		return client.Endpoint{}, err
	}
	cli := cpclient.New(platform)
	ep, err := cli.GetEndpointFull(peerID)
	if err != nil {
		return client.Endpoint{}, fmt.Errorf("peer %s endpoint: %w", peerID, err)
	}
	kind := transport.KindTLS
	if strings.EqualFold(ep.Transport, "quic") {
		kind = transport.KindQUIC
	}
	addrs := endpointDialOrder(ep)
	if len(addrs) == 0 {
		return client.Endpoint{}, fmt.Errorf("peer %s endpoint: no dial candidates", peerID)
	}
	return client.Endpoint{
		Kind:       kind,
		Address:    addrs[0],
		CertFP:     ep.CertFP,
		Candidates: addrs[1:],
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

// resolveSessionRef maps alias → session id, or uses recent session when ref is empty.
func resolveSessionRef(opts options, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = recent.SessionPlaceholder(opts.recent)
		if ref == "" {
			return "", fmt.Errorf("session id required (no recent session; pass <session_id|alias>)")
		}
	}
	doc, err := alias.Load(opts.aliases)
	if err != nil {
		return "", err
	}
	return doc.Resolve(ref), nil
}

func run(opts options) error {
	switch opts.cmd {
	case "keygen":
		return runKeygen(opts)
	case "up":
		return runUp(opts)
	case "serve":
		fmt.Fprintln(os.Stderr, "note: 'tyd serve' is deprecated; prefer 'tyd up'")
		return runUp(opts)
	case "register":
		return runRegister(opts)
	case "invite":
		return runInvite(opts)
	case "accept":
		return runAccept(opts)
	case "revoke":
		return runRevoke(opts)
	case "status":
		return runStatus(opts)
	case "alias":
		return runAlias(opts)
	case "session":
		return runSession(opts)
	case "create", "list", "attach", "close":
		return fmt.Errorf("unknown command %q; use: tyd session %s", opts.cmd, opts.cmd)
	default:
		return fmt.Errorf("unknown command %q", opts.cmd)
	}
}

func runSession(opts options) error {
	if len(opts.rest) == 0 {
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	st := newConnectStatus(os.Stderr, opts.verbose)
	switch sub {
	case "create":
		st.Log("Resolving endpoint.")
		ep, peerID, err := endpoint(opts)
		if err != nil {
			st.Clear()
			return err
		}
		bindSessionProgress(&ep, st)
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		info, err := client.Create(ep, key, client.CreateOpts{})
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, info.ID)
		rememberSession(opts, catalog.FromInfo(info, peerID, ep.Address, ep.CertFP, string(ep.Kind), ep.Candidates))
		if info.State == string(session.StatePending) {
			st.Clear()
			fmt.Fprintln(os.Stderr, "pending approval")
			fmt.Println(info.ID)
			return nil
		}
		if opts.detach {
			st.Clear()
			fmt.Println(info.ID)
			return nil
		}
		err = client.Attach(ep, key, info.ID, os.Stdin, os.Stdout)
		st.Clear()
		return err
	case "list":
		return runSessionList(opts)
	case "attach":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session attach [session_id|alias]: %w", err)
		}
		st.Log("Resolving endpoint.")
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			st.Clear()
			return err
		}
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, st, sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			return client.Attach(ep, key, sid, os.Stdin, os.Stdout)
		})
		st.Clear()
		return err
	case "watch":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session watch [session_id|alias]: %w", err)
		}
		st.Log("Resolving endpoint.")
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			st.Clear()
			return err
		}
		if peerID != "" {
			st.Log(fmt.Sprintf("Peer %s via %s.", shortPeer(peerID), ep.Kind))
		} else {
			st.Log(fmt.Sprintf("Local %s.", ep.Kind))
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			st.Clear()
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, st, sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			return client.Watch(ep, key, sid, os.Stdout)
		})
		st.Clear()
		return err
	case "close":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session close [session_id|alias]: %w", err)
		}
		ep, peerID, fromCatalog, err := endpointForSession(opts, sid)
		if err != nil {
			return err
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		err = withEndpointRetry(opts, newConnectStatus(os.Stderr, false), sid, peerID, ep, fromCatalog, func(ep client.Endpoint) error {
			return client.CloseSession(ep, key, sid)
		})
		if err != nil {
			return err
		}
		if rec, ok := loadLocalCatalog(opts).Get(sid); ok {
			rec.State = string(session.StateClosed)
			rememberSession(opts, rec)
		}
		return nil
	case "approve":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session approve [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		local := client.Endpoint{Kind: transport.KindUnix, Address: opts.socket}
		info, err := client.Approve(local, key, sid)
		if err != nil {
			return err
		}
		fmt.Println(info.ID)
		return nil
	case "reject":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session reject [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		local := client.Endpoint{Kind: transport.KindUnix, Address: opts.socket}
		return client.Reject(local, key, sid)
	case "help", "-h", "--help":
		writeSessionHelp(os.Stderr, colorEnabled(os.Stderr))
		return nil
	default:
		return fmt.Errorf("unknown session command %q\n%s", sub, sessionUsage())
	}
}

func runSessionList(opts options) error {
	cat := loadLocalCatalog(opts)
	adoc, _ := alias.Load(opts.aliases)
	items := cat.List()
	rows := make([]sessionListRow, 0, len(items))
	for _, it := range items {
		an := ""
		if adoc != nil {
			an = adoc.NameFor(it.ID)
		}
		peer := it.PeerID
		if peer == "" {
			peer = "-"
		}
		rows = append(rows, sessionListRow{
			ID: it.ID, Alias: an, Peer: peer,
			State: it.State, Created: catalog.CreatedDisplay(it),
		})
	}
	writeSessionList(os.Stdout, rows, colorEnabled(os.Stdout))
	return nil
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func runAlias(opts options) error {
	doc, err := alias.Load(opts.aliases)
	if err != nil {
		return err
	}
	if len(opts.rest) == 0 || opts.rest[0] == "list" {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ALIAS\tSESSION\tPEER")
		for _, e := range doc.Aliases {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.SessionID, e.PeerID)
		}
		return tw.Flush()
	}
	sub := opts.rest[0]
	args := opts.rest[1:]
	switch sub {
	case "rm", "remove", "unset":
		if len(args) != 1 {
			return fmt.Errorf("usage: tyd alias rm <name>")
		}
		if err := doc.Remove(args[0]); err != nil {
			return err
		}
		return alias.Save(opts.aliases, doc)
	case "set":
		if len(args) != 2 {
			return fmt.Errorf("usage: tyd alias set <session_id|alias> <name>")
		}
		sid, err := resolveSessionRef(opts, args[0])
		if err != nil {
			return err
		}
		peerID := ""
		if rec, _ := recent.Load(opts.recent); rec != nil {
			peerID = rec.PeerID
		}
		if err := doc.Set(args[1], sid, peerID); err != nil {
			return err
		}
		if err := alias.Save(opts.aliases, doc); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", args[1], sid)
		return nil
	default:
		// tyd alias <name>                 — alias the recent session
		// tyd alias <session_id> <name>    — alias an explicit session
		var sid, name string
		switch len(opts.rest) {
		case 1:
			name = opts.rest[0]
			var err error
			sid, err = resolveSessionRef(opts, "")
			if err != nil {
				return fmt.Errorf("usage: tyd alias <name> (needs a recent session), or tyd alias <session_id> <name>")
			}
		case 2:
			var err error
			sid, err = resolveSessionRef(opts, opts.rest[0])
			if err != nil {
				return err
			}
			name = opts.rest[1]
		default:
			return fmt.Errorf("usage: tyd alias [<session_id>] <name> | tyd alias list | tyd alias rm <name>")
		}
		peerID := ""
		if rec, _ := recent.Load(opts.recent); rec != nil {
			peerID = rec.PeerID
		}
		if err := doc.Set(name, sid, peerID); err != nil {
			return err
		}
		if err := alias.Save(opts.aliases, doc); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", name, sid)
		return nil
	}
}

func runStatus(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	platform, _ := platformFor(opts)
	fmt.Println("Control Panel")
	fmt.Printf("  platform:   %s\n", platform)
	if doc.HasRegistration() {
		reg := doc.Registration
		url := reg.URL
		if url == "" {
			url = platform + "/" + reg.ID
		}
		fmt.Printf("  registered: %s\n", url)
		fmt.Printf("  id:         %s\n", reg.ID)
		fmt.Printf("  approval:   %s\n", reg.ApprovalMode)
		epAddr, epFP, epErr := cpclient.New(platform).GetEndpoint(reg.ID)
		if epErr != nil {
			fmt.Printf("  endpoint:   (none / expired)\n")
		} else {
			fmt.Printf("  endpoint:   %s  fp=%s\n", epAddr, shortFP(epFP))
		}
	} else {
		fmt.Println("  registered: (no)")
	}
	fmt.Println()
	fmt.Println("Peers")
	if len(doc.Peers) == 0 {
		fmt.Println("  (none)")
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNICK\tDIRECTION\tPAIRED")
		for _, p := range doc.Peers {
			nick := p.Nickname
			if nick == "" {
				nick = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, nick, p.Direction, p.PairedAt.Format(time.RFC3339))
		}
		_ = tw.Flush()
	}
	if rec, _ := recent.Load(opts.recent); rec != nil && (rec.PeerID != "" || rec.SessionID != "") {
		fmt.Println()
		fmt.Println("Recent")
		if rec.PeerID != "" {
			fmt.Printf("  peer:    %s\n", rec.PeerID)
		}
		if rec.SessionID != "" {
			fmt.Printf("  session: %s\n", rec.SessionID)
		}
	}
	if adoc, _ := alias.Load(opts.aliases); adoc != nil && len(adoc.Aliases) > 0 {
		fmt.Println()
		fmt.Println("Session aliases")
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ALIAS\tSESSION\tPEER")
		for _, e := range adoc.Aliases {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.SessionID, e.PeerID)
		}
		_ = tw.Flush()
	}

	fmt.Println()
	fmt.Println("Connections")
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	ep, _, err := endpoint(opts)
	if err != nil {
		return err
	}
	items, err := client.Status(ep, key)
	if err != nil {
		fmt.Printf("  (daemon unreachable: %v)\n", err)
		return nil
	}
	if len(items) == 0 {
		fmt.Println("  (none)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTRANSPORT\tREMOTE\tTLS\tSTATE\tPRINCIPAL\tSESSION\tSINCE")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\t%s\t%s\n",
			it.ID, it.Transport, it.RemoteAddr, it.TLS, it.State, it.Principal, it.SessionID, it.EstablishedAt)
	}
	return tw.Flush()
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

func shortPeer(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func loadIdentity(path string) (ed25519.PrivateKey, error) {
	key, err := auth.LoadIdentity(path)
	if err != nil {
		return nil, fmt.Errorf("load identity %s: %w (identity is created on first up/register/accept)", path, err)
	}
	return key, nil
}

func ensureIdentity(opts options) (ed25519.PrivateKey, error) {
	key, created, err := auth.EnsureIdentity(opts.identity, opts.trust)
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Fprintf(os.Stderr, "created identity %s\n", opts.identity)
	}
	return key, nil
}

func runKeygen(opts options) error {
	if _, err := os.Stat(opts.identity); err == nil {
		return fmt.Errorf("identity already exists: %s", opts.identity)
	}
	_, priv, err := auth.Generate()
	if err != nil {
		return err
	}
	if err := auth.WriteIdentity(opts.identity, priv); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(os.Stderr, "wrote %s\n", opts.identity)
	if _, err := os.Stat(opts.trust); os.IsNotExist(err) {
		if err := auth.WriteBootstrapTrust(opts.trust, "local", pub); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (list+create for this key)\n", opts.trust)
	}
	fmt.Println(auth.EncodePublic(pub))
	return nil
}

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
	approvalMode := controlpanel.DefaultApproval
	if doc, err := peers.Load(opts.peers); err == nil && doc.Registration != nil {
		if mode, err := controlpanel.NormalizeApproval(doc.Registration.ApprovalMode); err == nil {
			approvalMode = mode
		}
	}
	mgr := session.NewManager()
	srv := server.NewWithConfig(server.Config{
		Socket:       opts.socket,
		Listen:       opts.listen,
		DataListen:   dataListen,
		CertPath:     opts.cert,
		KeyPath:      opts.key,
		Mgr:          mgr,
		Trust:        trust,
		ApprovalMode: approvalMode,
	})
	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tyd listening unix %s\n", opts.socket)
	if approvalMode != controlpanel.ApprovalFull {
		fmt.Fprintf(os.Stderr, "tyd approval mode %s\n", approvalMode)
	}
	if opts.listen != "" && opts.listen != "off" {
		fmt.Fprintf(os.Stderr, "tyd listening tls  %s (cert fp %s)\n", srv.ListenAddr(), srv.TLSFingerprint())
	} else {
		fmt.Fprintln(os.Stderr, "tyd tls listen off (use --listen HOST:PORT to enable)")
	}

	stop := make(chan struct{})
	if err := ensureCPRegistration(opts); err != nil {
		fmt.Fprintf(os.Stderr, "cp registration restore skipped: %v\n", err)
	}
	if srv.DataPlaneAddr() != "" {
		cands := transport.PreferNonLoopback(transport.ExpandCandidates(srv.DataPlaneAddr(), opts.advertise))
		if len(cands) == 0 {
			fmt.Fprintln(os.Stderr, "tyd data-plane: no dial candidates")
		} else {
			pubAddr := cands[0]
			fmt.Fprintf(os.Stderr, "tyd data-plane tls %s (%d candidates published to CP)\n", pubAddr, len(cands))
			if err := syncPeersAndTrust(opts, trust); err != nil {
				fmt.Fprintf(os.Stderr, "cp peer sync skipped: %v\n", err)
			}
			if err := publishDataEndpoint(opts, pubAddr, srv.TLSFingerprintFull(), cands); err != nil {
				fmt.Fprintf(os.Stderr, "cp endpoint publish skipped: %v\n", err)
			}
			go dataPlaneMaintain(opts, trust, pubAddr, srv.TLSFingerprintFull(), cands, stop)
		}
	} else {
		if err := syncPeersFromCP(opts); err != nil {
			fmt.Fprintf(os.Stderr, "cp peer sync skipped: %v\n", err)
		}
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(stop)
	return srv.Close()
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

func ensureCPRegistration(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if !doc.HasRegistration() {
		return nil
	}
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
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

func publishDataEndpoint(opts options, addr, certFP string, candidates []string) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if !doc.HasRegistration() {
		return nil
	}
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(platform)
	ttlSec := int(controlpanel.DefaultEndpointTTL / time.Second)
	return cli.PublishEndpointFull(doc.Registration.ID, controlpanel.PublishEndpointRequest{
		PublicKey:  pub,
		Addr:       addr,
		CertFP:     certFP,
		Transport:  "tls",
		Candidates: candidates,
		TTLSeconds: ttlSec,
	})
}

func dataPlaneMaintain(opts options, trust *auth.Store, addr, certFP string, candidates []string, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := syncPeersAndTrust(opts, trust); err != nil {
				fmt.Fprintf(os.Stderr, "cp peer sync: %v\n", err)
			}
			if err := publishDataEndpoint(opts, addr, certFP, candidates); err != nil {
				fmt.Fprintf(os.Stderr, "cp endpoint publish: %v\n", err)
			}
		}
	}
}

func injectPeerTrust(trust *auth.Store, doc *peers.File) {
	if trust == nil || doc == nil {
		return
	}
	var keep []ed25519.PublicKey
	for _, p := range doc.Peers {
		if p.Direction != "inbound" && p.Direction != "" {
			continue
		}
		pub, err := auth.DecodePublic(p.PublicKey)
		if err != nil {
			continue
		}
		name := p.Nickname
		if name == "" {
			name = p.ID
		}
		trust.EnsurePeer(name, pub, auth.AllGlobal)
		keep = append(keep, pub)
	}
	trust.DropUnlistedPeers(keep)
}

func syncPeersAndTrust(opts options, trust *auth.Store) error {
	if err := syncPeersFromCP(opts); err != nil {
		return err
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	injectPeerTrust(trust, doc)
	return nil
}

func runRegister(opts options) error {
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	force := opts.force
	if doc.HasRegistration() {
		if err := confirmReregister(force); err != nil {
			return err
		}
		force = true
		fmt.Fprintln(os.Stderr, "warning: re-registering replaces this daemon on the Control Panel and invalidates existing peer pairings.")
	}
	platform := opts.platform
	if !force && doc.Platform != "" {
		platform = doc.Platform
	}
	cli := cpclient.New(platform)
	reg, err := cli.RegisterOpts(pub, opts.approval, force)
	if err != nil {
		return err
	}
	inv, err := cli.CreateInvite(reg.ID, pub)
	if err != nil {
		return err
	}
	doc.Platform = cli.BaseURL
	doc.Registration = &peers.Registration{
		ID:           reg.ID,
		PublicKey:    pub,
		ApprovalMode: reg.ApprovalMode,
		URL:          reg.URL,
		RegisteredAt: time.Now().UTC(),
	}
	var baseline map[string]struct{}
	if force {
		doc.Peers = nil
		baseline = map[string]struct{}{}
	} else if remote, err := cli.ListPeers(reg.ID, pub); err == nil {
		doc.MergePeers(cpPeersToLocal(remote))
		baseline = peerIDSet(remote)
	} else {
		baseline = map[string]struct{}{}
	}
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	printInviteResult(os.Stderr, os.Stdout, inviteResult{
		Kind:      "registered",
		URL:       reg.URL,
		Approval:  reg.ApprovalMode,
		Platform:  cli.BaseURL,
		Token:     inv.Token,
		TTL:       controlpanel.InviteTTL,
		ExpiresAt: inv.ExpiresAt,
	})
	return waitForInviteAccept(opts, cli, reg.ID, pub, inv.Token, inv.ExpiresAt, baseline)
}

func confirmReregister(force bool) error {
	if force {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return fmt.Errorf("already registered; re-register requires --force (invalidates existing peers)")
	}
	fmt.Fprint(os.Stderr, "Already registered. Re-registering invalidates all existing peers. Continue? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans != "y" && ans != "yes" {
		return fmt.Errorf("aborted")
	}
	return nil
}

func runInvite(opts options) error {
	if len(opts.rest) > 0 && (opts.rest[0] == "revoke" || opts.rest[0] == "rm") {
		if len(opts.rest) != 2 {
			return fmt.Errorf("usage: tyd invite revoke <token>")
		}
		return runRevokeInvite(opts, opts.rest[1])
	}
	if len(opts.rest) != 0 {
		return fmt.Errorf("usage: tyd invite | tyd invite revoke <token>")
	}
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if !doc.HasRegistration() {
		return fmt.Errorf("not registered; run: tyd register")
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
	cli := cpclient.New(platform)
	inv, err := cli.CreateInvite(doc.Registration.ID, pub)
	if err != nil {
		return err
	}
	url := ""
	if doc.Registration != nil {
		url = doc.Registration.URL
		if url == "" && doc.Registration.ID != "" {
			url = strings.TrimRight(cli.BaseURL, "/") + "/" + doc.Registration.ID
		}
	}
	baseline := map[string]struct{}{}
	if remote, err := cli.ListPeers(doc.Registration.ID, pub); err == nil {
		doc.MergePeers(cpPeersToLocal(remote))
		_ = peers.Save(opts.peers, doc)
		baseline = peerIDSet(remote)
	}
	printInviteResult(os.Stderr, os.Stdout, inviteResult{
		Kind:      "invite",
		URL:       url,
		Approval:  doc.Registration.ApprovalMode,
		Platform:  cli.BaseURL,
		Token:     inv.Token,
		TTL:       controlpanel.InviteTTL,
		ExpiresAt: inv.ExpiresAt,
	})
	return waitForInviteAccept(opts, cli, doc.Registration.ID, pub, inv.Token, inv.ExpiresAt, baseline)
}

func peerIDSet(list []controlpanel.Peer) map[string]struct{} {
	out := make(map[string]struct{}, len(list))
	for _, p := range list {
		out[p.ID] = struct{}{}
	}
	return out
}

func formatRemaining(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	return d.String()
}

// After printInviteResult, stderr looks like:
//
//	invite ttl …
//	<blank>
//	Copy and run on the peer:
//	  tyd accept …
//
// From the line after the accept command, move up to rewrite the ttl row.
const (
	inviteTTLCursorUp   = 4
	inviteTTLCursorDown = 3
)

func rewriteInviteTTL(expiresAt time.Time, color bool, desc string) {
	if desc == "" {
		desc = formatRemaining(time.Until(expiresAt))
	}
	fmt.Fprintf(os.Stderr, "\033[%dA\r\033[K", inviteTTLCursorUp)
	writeHelpRows(os.Stderr, []helpRow{{"invite ttl", desc}}, color)
	fmt.Fprintf(os.Stderr, "\033[%dB", inviteTTLCursorDown)
}

// waitForInviteAccept keeps the process alive until a peer accepts the invite,
// the TTL expires, or the user cancels (Ctrl-C revokes the invite).
// On a TTY, the "invite ttl" help row is refreshed in place.
func waitForInviteAccept(opts options, cli *cpclient.Client, daemonID, pub, token string, expiresAt time.Time, baseline map[string]struct{}) error {
	if opts.noWait {
		return nil
	}
	if baseline == nil {
		baseline = map[string]struct{}{}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	tty := colorEnabled(os.Stderr)
	color := tty

	for {
		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			if tty {
				rewriteInviteTTL(expiresAt, color, "expired")
			}
			return fmt.Errorf("invite expired")
		}
		select {
		case <-sig:
			if err := cli.RevokeInvite(token, daemonID, pub); err != nil {
				return fmt.Errorf("invite cancelled (revoke failed: %v)", err)
			}
			return fmt.Errorf("invite revoked")
		case <-ticker.C:
			if tty {
				rewriteInviteTTL(expiresAt, color, "")
			}
			remote, err := cli.ListPeers(daemonID, pub)
			if err != nil {
				continue
			}
			for _, p := range remote {
				if _, seen := baseline[p.ID]; seen {
					continue
				}
				doc, err := peers.Load(opts.peers)
				if err != nil {
					return err
				}
				doc.MergePeers(cpPeersToLocal(remote))
				if err := peers.Save(opts.peers, doc); err != nil {
					return err
				}
				if p.Nickname != "" {
					fmt.Fprintf(os.Stderr, "paired %s (%s)\n", p.ID, p.Nickname)
				} else {
					fmt.Fprintf(os.Stderr, "paired %s\n", p.ID)
				}
				return nil
			}
		}
	}
}

func runRevokeInvite(opts options, token string) error {
	key, err := loadIdentity(opts.identity)
	if err != nil {
		return err
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if !doc.HasRegistration() {
		return fmt.Errorf("not registered; run: tyd register")
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
	cli := cpclient.New(platform)
	if err := cli.RevokeInvite(token, doc.Registration.ID, pub); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "invite revoked")
	return nil
}

func runRevoke(opts options) error {
	if len(opts.rest) != 1 {
		return fmt.Errorf("usage: tyd revoke <peer-id|nickname>")
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	p, err := doc.Find(opts.rest[0])
	if err != nil {
		return err
	}
	if doc.HasRegistration() {
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
		platform := opts.platform
		if doc.Platform != "" {
			platform = doc.Platform
		}
		cli := cpclient.New(platform)
		if err := cli.RevokePeer(doc.Registration.ID, pub, p.ID); err != nil {
			return err
		}
	}
	if _, err := doc.RemovePeer(p.ID); err != nil {
		return err
	}
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked peer %s\n", p.ID)
	fmt.Println(p.ID)
	return nil
}

func runAccept(opts options) error {
	if len(opts.rest) != 1 {
		return fmt.Errorf("usage: tyd accept <invite-token> [--as nickname]")
	}
	token := parseInviteToken(opts.rest[0])
	if token == "" {
		return fmt.Errorf("usage: tyd accept <invite-token> [--as nickname]")
	}
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(opts.platform)
	acc, err := cli.Accept(token, pub, opts.as)
	if err != nil {
		return err
	}
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	doc.Platform = cli.BaseURL
	if doc.Registration == nil {
		doc.Registration = &peers.Registration{
			ID:           acc.SelfID,
			PublicKey:    pub,
			ApprovalMode: controlpanel.DefaultApproval,
			RegisteredAt: time.Now().UTC(),
		}
	} else {
		doc.Registration.ID = acc.SelfID
		doc.Registration.PublicKey = pub
	}
	doc.UpsertPeer(peers.Peer{
		ID:        acc.PeerID,
		PublicKey: acc.PeerPublicKey,
		Nickname:  acc.PeerNickname,
		Direction: "outbound",
		PairedAt:  time.Now().UTC(),
	})
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "paired with %s\n", acc.PeerID)
	fmt.Println(acc.PeerID)
	return nil
}

func syncPeersFromCP(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if doc.Registration == nil || doc.Registration.ID == "" {
		return nil
	}
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
	key, err := auth.LoadIdentity(opts.identity)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(platform)
	remote, err := cli.ListPeers(doc.Registration.ID, pub)
	if err != nil {
		return err
	}
	doc.ReplaceFromRemote(cpPeersToLocal(remote))
	return peers.Save(opts.peers, doc)
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

func parseArgs(args []string) (options, error) {
	opts := options{
		socket:     paths.DefaultSocket(),
		listen:     paths.DefaultListen(),
		dataListen: paths.DefaultDataListen(),
		advertise:  paths.DefaultAdvertise(),
		identity:   paths.DefaultIdentity(),
		trust:      paths.DefaultTrust(),
		peers:      paths.DefaultPeers(),
		recent:     paths.DefaultRecent(),
		aliases:    paths.DefaultAliases(),
		sessions:   paths.DefaultSessions(),
		platform:   paths.DefaultPlatform(),
		approval:   controlpanel.DefaultApproval,
		cert:       paths.DefaultServerCert(),
		key:        paths.DefaultServerKey(),
	}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			opts.cmd = "help"
			return opts, nil
		case a == "--socket" || a == "-socket":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.socket = args[i]
		case strings.HasPrefix(a, "--socket="):
			opts.socket = strings.TrimPrefix(a, "--socket=")
		case a == "--listen":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires an address or 'off'", a)
			}
			i++
			opts.listen = args[i]
		case strings.HasPrefix(a, "--listen="):
			opts.listen = strings.TrimPrefix(a, "--listen=")
		case a == "--data-listen":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires auto|off|HOST:PORT", a)
			}
			i++
			opts.dataListen = args[i]
		case strings.HasPrefix(a, "--data-listen="):
			opts.dataListen = strings.TrimPrefix(a, "--data-listen=")
		case a == "--advertise":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a host", a)
			}
			i++
			opts.advertise = args[i]
		case strings.HasPrefix(a, "--advertise="):
			opts.advertise = strings.TrimPrefix(a, "--advertise=")
		case a == "--addr":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires host:port", a)
			}
			i++
			opts.addr = args[i]
		case strings.HasPrefix(a, "--addr="):
			opts.addr = strings.TrimPrefix(a, "--addr=")
		case a == "--peer":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires an id or nickname", a)
			}
			i++
			opts.peer = args[i]
		case strings.HasPrefix(a, "--peer="):
			opts.peer = strings.TrimPrefix(a, "--peer=")
		case a == "--identity":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.identity = args[i]
		case strings.HasPrefix(a, "--identity="):
			opts.identity = strings.TrimPrefix(a, "--identity=")
		case a == "--trust":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.trust = args[i]
		case strings.HasPrefix(a, "--trust="):
			opts.trust = strings.TrimPrefix(a, "--trust=")
		case a == "--peers":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.peers = args[i]
		case strings.HasPrefix(a, "--peers="):
			opts.peers = strings.TrimPrefix(a, "--peers=")
		case a == "--aliases":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.aliases = args[i]
		case strings.HasPrefix(a, "--aliases="):
			opts.aliases = strings.TrimPrefix(a, "--aliases=")
		case a == "--recent":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.recent = args[i]
		case strings.HasPrefix(a, "--recent="):
			opts.recent = strings.TrimPrefix(a, "--recent=")
		case a == "--platform":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a URL", a)
			}
			i++
			opts.platform = args[i]
		case strings.HasPrefix(a, "--platform="):
			opts.platform = strings.TrimPrefix(a, "--platform=")
		case a == "--approval":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires full|pre|post", a)
			}
			i++
			opts.approval = args[i]
		case strings.HasPrefix(a, "--approval="):
			opts.approval = strings.TrimPrefix(a, "--approval=")
		case a == "--as":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a nickname", a)
			}
			i++
			opts.as = args[i]
		case strings.HasPrefix(a, "--as="):
			opts.as = strings.TrimPrefix(a, "--as=")
		case a == "--no-wait":
			opts.noWait = true
		case a == "--detach":
			opts.detach = true
		case a == "--verbose":
			opts.verbose = true
		case a == "--force":
			opts.force = true
		case a == "--tls-cert":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.cert = args[i]
		case strings.HasPrefix(a, "--tls-cert="):
			opts.cert = strings.TrimPrefix(a, "--tls-cert=")
		case a == "--tls-key":
			if i+1 >= len(args) {
				return options{}, fmt.Errorf("%s requires a path", a)
			}
			i++
			opts.key = args[i]
		case strings.HasPrefix(a, "--tls-key="):
			opts.key = strings.TrimPrefix(a, "--tls-key=")
		case strings.HasPrefix(a, "-"):
			return options{}, fmt.Errorf("unknown flag %s", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		return opts, nil
	}
	opts.cmd = positional[0]
	opts.rest = positional[1:]
	return opts, nil
}

func colorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

type sessionListRow struct {
	ID, Alias, Peer, State, Created string
}

func liveState(state string) bool {
	return strings.EqualFold(strings.TrimSpace(state), "ATTACHED")
}

func padCell(s string, width int) string {
	if width < len(s) {
		width = len(s)
	}
	return fmt.Sprintf("%-*s", width, s)
}

func paintCell(s string, width int, color bool) string {
	padded := padCell(s, width)
	if !color {
		return padded
	}
	return ansiCyan + padded + ansiReset
}

func writeSessionList(w io.Writer, rows []sessionListRow, color bool) {
	idW, aliasW, peerW, stateW, createdW := len("SESSION"), len("ALIAS"), len("PEER"), len("STATE"), len("CREATED")
	for _, r := range rows {
		idW = max(idW, len(r.ID))
		aliasW = max(aliasW, len(r.Alias))
		peerW = max(peerW, len(r.Peer))
		stateW = max(stateW, len(r.State))
		createdW = max(createdW, len(r.Created))
	}
	const gap = "  "
	fmt.Fprint(w, padCell("SESSION", idW), gap)
	fmt.Fprint(w, padCell("ALIAS", aliasW), gap)
	fmt.Fprint(w, padCell("PEER", peerW), gap)
	fmt.Fprint(w, padCell("STATE", stateW), gap)
	fmt.Fprintln(w, padCell("CREATED", createdW))
	for _, r := range rows {
		fmt.Fprint(w, padCell(r.ID, idW), gap)
		fmt.Fprint(w, paintCell(r.Alias, aliasW, color && r.Alias != ""), gap)
		fmt.Fprint(w, padCell(r.Peer, peerW), gap)
		fmt.Fprint(w, paintCell(r.State, stateW, color && liveState(r.State)), gap)
		fmt.Fprintln(w, padCell(r.Created, createdW))
	}
}

type inviteResult struct {
	Kind      string // registered | invite
	URL       string
	Approval  string
	Platform  string
	Token     string
	TTL       time.Duration
	ExpiresAt time.Time
}

// formatAcceptCommand returns a shell line the peer can paste as-is.
// --platform is included only when it differs from the built-in default.
func formatAcceptCommand(platform, token string) string {
	platform = strings.TrimRight(strings.TrimSpace(platform), "/")
	def := strings.TrimRight(paths.DefaultPlatform(), "/")
	if platform == "" || strings.EqualFold(platform, def) {
		return "tyd accept " + token
	}
	return fmt.Sprintf("tyd --platform %s accept %s", platform, token)
}

// parseInviteToken accepts a bare token or a pasted "tyd … accept <token>" line.
func parseInviteToken(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}
	fields := strings.Fields(arg)
	for i, f := range fields {
		if f == "accept" && i+1 < len(fields) {
			tok := fields[i+1]
			if tok == "" || strings.HasPrefix(tok, "-") {
				return ""
			}
			return tok
		}
	}
	if len(fields) == 1 {
		return fields[0]
	}
	return ""
}

func printInviteResult(errW, outW io.Writer, r inviteResult) {
	color := colorEnabled(errW)
	switch r.Kind {
	case "registered":
		fmt.Fprintln(errW, "Registered with Control Panel.")
	default:
		fmt.Fprintln(errW, "Invite minted.")
	}
	fmt.Fprintln(errW)
	ttl := r.TTL.String()
	if !r.ExpiresAt.IsZero() {
		ttl = formatRemaining(time.Until(r.ExpiresAt))
	}
	rows := make([]helpRow, 0, 3)
	if r.URL != "" {
		rows = append(rows, helpRow{"url", r.URL})
	}
	if r.Approval != "" {
		rows = append(rows, helpRow{"approval", r.Approval})
	}
	rows = append(rows, helpRow{"invite ttl", ttl})
	writeHelpRows(errW, rows, color)
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "Copy and run on the peer:")
	cmd := formatAcceptCommand(r.Platform, r.Token)
	if color {
		fmt.Fprintf(errW, "  %s%s%s\n", ansiCyan, cmd, ansiReset)
	} else {
		fmt.Fprintf(errW, "  %s\n", cmd)
	}
	// Avoid a duplicate line when both stderr and stdout are the terminal.
	// Scripts that capture stdout still get the command (stdout is then a pipe).
	if !colorEnabled(outW) || !colorEnabled(errW) {
		fmt.Fprintln(outW, cmd)
	}
}

func writeHelpRows(w io.Writer, rows []helpRow, color bool) {
	for _, r := range rows {
		name := r.name
		pad := helpColPad - len(name)
		if pad < 2 {
			pad = 2
		}
		if color {
			fmt.Fprintf(w, "  %s%s%s%s%s\n", ansiCyan, name, ansiReset, strings.Repeat(" ", pad), r.desc)
			continue
		}
		fmt.Fprintf(w, "  %-*s%s\n", helpColPad, name, r.desc)
	}
}

func writeRootHelp(w io.Writer, color bool) {
	fmt.Fprintln(w, "Persistent, remotely attachable terminal sessions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd [command] [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Common commands:")
	writeHelpRows(w, []helpRow{
		{"session create", "Create a session and attach (use --detach for id only)"},
		{"session list", "List local sessions (alive first, newest first)"},
		{"session attach", "Attach to a session (id, alias, or recent)"},
		{"session watch", "Follow session output (read-only)"},
		{"session approve", "Approve a PENDING remote session (local unix)"},
		{"session reject", "Reject a PENDING remote session (local unix)"},
		{"session close", "Close a session (kept as history)"},
		{"alias", "Name a session for later attach/watch/close"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Identity / pairing:")
	writeHelpRows(w, []helpRow{
		{"keygen", "Generate Ed25519 identity (optional; also auto-created)"},
		{"register", "Register; print tyd accept … and wait for peer"},
		{"--force", "register: replace existing registration (invalidates peers)"},
		{"invite", "Mint invite; print tyd accept … and wait (10m TTL)"},
		{"accept", "Accept a peer invite (token or pasted accept line)"},
		{"revoke", "Revoke a paired peer (either side)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Daemon:")
	writeHelpRows(w, []helpRow{
		{"up", "Start the tyd daemon (unix socket; TLS off by default)"},
		{"serve", "Alias for up (deprecated)"},
		{"status", "Show CP registration, peers, and connections"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	writeHelpRows(w, []helpRow{
		{"--socket PATH", fmt.Sprintf("Unix socket (default %s)", paths.DefaultSocket())},
		{"--listen ADDR|off", fmt.Sprintf("Manual TLS listen for up (default %s)", paths.DefaultListen())},
		{"--data-listen MODE", "Data-plane TLS: auto|off|HOST:PORT (default auto)"},
		{"--advertise HOST", "Host to prefer in CP candidates (default: auto interface IPs)"},
		{"--addr HOST:PORT", "TLS client endpoint (local override)"},
		{"--peer ID|NICK", "Target paired peer for session commands"},
		{"--identity PATH", fmt.Sprintf("Client identity (default %s)", paths.DefaultIdentity())},
		{"--trust PATH", fmt.Sprintf("Trust file (default %s)", paths.DefaultTrust())},
		{"--peers PATH", fmt.Sprintf("Paired peers file (default %s)", paths.DefaultPeers())},
		{"--aliases PATH", fmt.Sprintf("Session aliases file (default %s)", paths.DefaultAliases())},
		{"--platform URL", fmt.Sprintf("Control Panel URL (default %s)", paths.DefaultPlatform())},
		{"--approval MODE", "Register approval: full|pre|post (default full)"},
		{"--as NAME", "Peer nickname when accepting an invite"},
		{"--no-wait", "register/invite: exit after printing accept (no countdown)"},
		{"--detach", "session create: print id only (do not attach)"},
		{"--verbose", "session create/attach/watch: print connect debug (ssh -v style)"},
		{"--tls-cert PATH", fmt.Sprintf("Server cert / client pin (default %s)", paths.DefaultServerCert())},
		{"--tls-key PATH", "Server key"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  While connecting, Ctrl-C cancels; while attached, Ctrl-\\ detaches.")
	fmt.Fprintln(w, "  While watching, Ctrl-C or Ctrl-\\ stops; the session is not closed.")
	fmt.Fprintln(w, "  Use --peer <id|nickname> for create/attach/watch/close on a paired peer.")
	fmt.Fprintln(w, "  session list is local (sessions.json); it does not use --peer or CP.")
	fmt.Fprintln(w, "  tyd revoke <peer> drops a pairing; tyd invite revoke <token> drops an unused invite.")
	fmt.Fprintln(w, "  register/invite wait for accept by default; Ctrl-C revokes the invite; --no-wait skips wait.")
	fmt.Fprintln(w, "  Omit session id to reuse the most recent session (see tyd status / recent.json).")
	fmt.Fprintln(w, "  Pairing: see docs/requirements/control-plane-pairing.md")
}

func writeSessionHelp(w io.Writer, color bool) {
	ph := recent.SessionPlaceholder(paths.DefaultRecent())
	attachEx := "attach [session_id|alias]"
	if ph != "" {
		attachEx = "attach [" + ph + "]"
	}
	fmt.Fprintln(w, "Manage persistent PTY sessions.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  tyd session [command]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	writeHelpRows(w, []helpRow{
		{"create", "Create and attach (interactive; Ctrl-\\ detaches)"},
		{"list", "List local sessions (alive first, newest first)"},
		{"attach", "Attach (id, alias, or omit for recent)"},
		{"watch", "Follow output (id, alias, or omit for recent)"},
		{"approve", "Approve PENDING session (local unix only)"},
		{"reject", "Reject PENDING session (local unix only)"},
		{"close", "Close a session (kept as history)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintf(w, "  %-24s Interactive; Ctrl-\\ detaches.\n", attachEx)
	fmt.Fprintln(w, "  create --detach          Print session id only (for scripts).")
	fmt.Fprintln(w, "  --verbose                SSH-style connect debug on stderr.")
	fmt.Fprintln(w, "  watch [session_id|alias]  Read-only; Ctrl-C / Ctrl-\\ stops.")
	fmt.Fprintln(w, "  approve [id|alias]        Start PTY for a PENDING remote create.")
	fmt.Fprintln(w, "  reject [id|alias]         Remove a PENDING session.")
	fmt.Fprintln(w, "  close [id|alias]          Marks CLOSED; kept until daemon restart.")
	fmt.Fprintln(w, "  Omit the id to reuse the most recent session (recent.json).")
	fmt.Fprintln(w, "  --peer <id|nick>          Target a paired peer for dialing commands.")
	fmt.Fprintln(w, "  session list              Local catalog only (no CP / daemon).")
	fmt.Fprintln(w, "  tyd alias <name>          Name the recent session for later use.")
}

func sessionUsage() string {
	var b strings.Builder
	writeSessionHelp(&b, false)
	return b.String()
}

func usage() {
	writeRootHelp(os.Stderr, colorEnabled(os.Stderr))
}
