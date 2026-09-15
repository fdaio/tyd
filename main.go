package main

import (
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
	platform   string
	approval   string
	as         string
	cert       string
	key        string
	cmd        string
	rest       []string
}

func main() {
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
	addr, certFP, err := cli.GetEndpoint(peerID)
	if err != nil {
		return client.Endpoint{}, "", fmt.Errorf("peer %s endpoint: %w", peerID, err)
	}
	return client.Endpoint{
		Kind:    transport.KindTLS,
		Address: addr,
		CertFP:  certFP,
	}, peerID, nil
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
	case "accept":
		return runAccept(opts)
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
	ep, peerID, err := endpoint(opts)
	if err != nil {
		return err
	}
	switch sub {
	case "create":
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		info, err := client.Create(ep, key, client.CreateOpts{})
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, info.ID)
		if info.State == string(session.StatePending) {
			fmt.Fprintln(os.Stderr, "pending approval")
		}
		fmt.Println(info.ID)
		return nil
	case "list":
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		items, err := client.List(ep, key)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, "")
		adoc, _ := alias.Load(opts.aliases)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SESSION\tALIAS\tPID\tSTATE\tSIZE\tCREATED")
		for _, it := range items {
			an := ""
			if adoc != nil {
				an = adoc.NameFor(it.ID)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%dx%d\t%s\n", it.ID, an, it.PID, it.State, it.Cols, it.Rows, it.CreatedAt)
		}
		return tw.Flush()
	case "attach":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session attach [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		fmt.Fprintf(os.Stderr, "attached to %s  detach: Ctrl-\\\n", sid)
		return client.Attach(ep, key, sid, os.Stdin, os.Stdout)
	case "watch":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session watch [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		fmt.Fprintf(os.Stderr, "watching %s  exit: Ctrl-C or Ctrl-\\\n", sid)
		return client.Watch(ep, key, sid, os.Stdout)
	case "close":
		sid, err := resolveSessionRef(opts, firstArg(args))
		if err != nil {
			return fmt.Errorf("usage: tyd session close [session_id|alias]: %w", err)
		}
		key, err := loadIdentity(opts.identity)
		if err != nil {
			return err
		}
		rememberPeerSession(opts, peerID, sid)
		return client.CloseSession(ep, key, sid)
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
	if srv.DataPlaneAddr() != "" {
		pubAddr := advertisedAddr(opts.advertise, srv.DataPlaneAddr())
		fmt.Fprintf(os.Stderr, "tyd data-plane tls %s (published to CP)\n", pubAddr)
		if err := syncPeersAndTrust(opts, trust); err != nil {
			fmt.Fprintf(os.Stderr, "cp peer sync skipped: %v\n", err)
		}
		if err := publishDataEndpoint(opts, pubAddr, srv.TLSFingerprintFull()); err != nil {
			fmt.Fprintf(os.Stderr, "cp endpoint publish skipped: %v\n", err)
		}
		go dataPlaneMaintain(opts, trust, pubAddr, srv.TLSFingerprintFull(), stop)
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
			return "127.0.0.1:0", nil
		}
		return "off", nil
	default:
		return v, nil
	}
}

func advertisedAddr(host, listenAddr string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = paths.DefaultAdvertise()
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	return net.JoinHostPort(host, port)
}

func publishDataEndpoint(opts options, addr, certFP string) error {
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
	return cli.PublishEndpoint(doc.Registration.ID, pub, addr, certFP, controlpanel.DefaultEndpointTTL)
}

func injectPeerTrust(trust *auth.Store, doc *peers.File) {
	if trust == nil || doc == nil {
		return
	}
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
	}
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

func dataPlaneMaintain(opts options, trust *auth.Store, addr, certFP string, stop <-chan struct{}) {
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
			if err := publishDataEndpoint(opts, addr, certFP); err != nil {
				fmt.Fprintf(os.Stderr, "cp endpoint publish: %v\n", err)
			}
		}
	}
}

func runRegister(opts options) error {
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(opts.platform)
	reg, err := cli.Register(pub, opts.approval)
	if err != nil {
		return err
	}
	inv, err := cli.CreateInvite(reg.ID, pub)
	if err != nil {
		return err
	}
	doc, err := peers.Load(opts.peers)
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
	if remote, err := cli.ListPeers(reg.ID, pub); err == nil {
		doc.MergePeers(cpPeersToLocal(remote))
	}
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "registered %s (approval %s)\n", reg.URL, reg.ApprovalMode)
	fmt.Fprintf(os.Stderr, "invite (TTL %s): %s\n", controlpanel.InviteTTL, inv.Token)
	fmt.Println(inv.Token)
	return nil
}

func runAccept(opts options) error {
	if len(opts.rest) != 1 {
		return fmt.Errorf("usage: tyd accept <invite-token> [--as nickname]")
	}
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(opts.platform)
	acc, err := cli.Accept(opts.rest[0], pub, opts.as)
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
	doc.MergePeers(cpPeersToLocal(remote))
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
		{"session create", "Create a persistent PTY session"},
		{"session list", "List sessions (alive first)"},
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
		{"register", "Register with Control Panel and print invite"},
		{"accept", "Accept a peer invite (stores peer public key)"},
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
		{"--advertise HOST", fmt.Sprintf("Host published to CP (default %s)", paths.DefaultAdvertise())},
		{"--addr HOST:PORT", "TLS client endpoint (local override)"},
		{"--peer ID|NICK", "Target paired peer for session commands"},
		{"--identity PATH", fmt.Sprintf("Client identity (default %s)", paths.DefaultIdentity())},
		{"--trust PATH", fmt.Sprintf("Trust file (default %s)", paths.DefaultTrust())},
		{"--peers PATH", fmt.Sprintf("Paired peers file (default %s)", paths.DefaultPeers())},
		{"--aliases PATH", fmt.Sprintf("Session aliases file (default %s)", paths.DefaultAliases())},
		{"--platform URL", fmt.Sprintf("Control Panel URL (default %s)", paths.DefaultPlatform())},
		{"--approval MODE", "Register approval: full|pre|post (default full)"},
		{"--as NAME", "Peer nickname when accepting an invite"},
		{"--tls-cert PATH", fmt.Sprintf("Server cert / client pin (default %s)", paths.DefaultServerCert())},
		{"--tls-key PATH", "Server key"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintln(w, "  While attached, Ctrl-\\ detaches; the shell keeps running.")
	fmt.Fprintln(w, "  While watching, Ctrl-C or Ctrl-\\ stops; the session is not closed.")
	fmt.Fprintln(w, "  Use --peer <id|nickname> to create/list sessions on a paired peer.")
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
		{"create", "Create a persistent PTY session"},
		{"list", "List sessions (alive first; PENDING counts as alive)"},
		{"attach", "Attach (id, alias, or omit for recent)"},
		{"watch", "Follow output (id, alias, or omit for recent)"},
		{"approve", "Approve PENDING session (local unix only)"},
		{"reject", "Reject PENDING session (local unix only)"},
		{"close", "Close a session (kept as history)"},
	}, color)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tips:")
	fmt.Fprintf(w, "  %-24s Interactive; Ctrl-\\ detaches.\n", attachEx)
	fmt.Fprintln(w, "  watch [session_id|alias]  Read-only; Ctrl-C / Ctrl-\\ stops.")
	fmt.Fprintln(w, "  approve [id|alias]        Start PTY for a PENDING remote create.")
	fmt.Fprintln(w, "  reject [id|alias]         Remove a PENDING session.")
	fmt.Fprintln(w, "  close [id|alias]          Marks CLOSED; kept until daemon restart.")
	fmt.Fprintln(w, "  Omit the id to reuse the most recent session (recent.json).")
	fmt.Fprintln(w, "  --peer <id|nick>          Target a paired peer (CP signaling + direct TLS).")
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
