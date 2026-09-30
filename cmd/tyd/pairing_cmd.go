package main

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"tyd/internal/archive"
	"tyd/internal/auth"
	"tyd/internal/catalog"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/paths"
	"tyd/internal/peers"
	"tyd/internal/peerstate"
)

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
	tok, secret, err := newPairingToken(inv.Token, key)
	if err != nil {
		return err
	}
	printInviteResult(os.Stderr, os.Stdout, inviteResult{
		Kind:      "registered",
		URL:       reg.URL,
		Approval:  reg.ApprovalMode,
		Platform:  cli.BaseURL,
		Relay:     relayURL(opts),
		Token:     tok,
		TTL:       controlpanel.InviteTTL,
		ExpiresAt: inv.ExpiresAt,
	})
	return waitForInviteAccept(opts, cli, key, reg.ID, pub, tok, secret, inv.Token, inv.ExpiresAt, baseline)
}

// parseIdleTimeout accepts a Go duration, or off/0/none for no reaping.
func parseIdleTimeout(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "off", "none", "0":
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("--session-idle-timeout %q: use a duration like 8h, or off", v)
	}
	if d < 0 {
		return 0, fmt.Errorf("--session-idle-timeout must not be negative")
	}
	return d, nil
}

// runApproval shows or changes the approval mode without re-registering, so
// the daemon id and existing pairings survive.
func runApproval(opts options) error {
	doc, err := peers.Load(opts.peers)
	if err != nil {
		return err
	}
	if !doc.HasRegistration() {
		return fmt.Errorf("not registered; run tyd register first")
	}
	if len(opts.rest) == 0 {
		fmt.Println(doc.Registration.ApprovalMode)
		return nil
	}
	if len(opts.rest) > 1 {
		return fmt.Errorf("usage: tyd approval [full|pre|post]")
	}
	mode, err := controlpanel.NormalizeApproval(opts.rest[0])
	if err != nil {
		return fmt.Errorf("%w (use full, pre, or post)", err)
	}
	platform := opts.platform
	if doc.Platform != "" {
		platform = doc.Platform
	}
	cli := cpclient.New(platform)
	if reg, err := cli.Register(doc.Registration.PublicKey, mode); err != nil {
		fmt.Fprintf(os.Stderr, "control panel not updated (%v); saving locally\n", err)
	} else if reg.ID != doc.Registration.ID {
		return fmt.Errorf("control panel returned id %s, expected %s; not saving", reg.ID, doc.Registration.ID)
	}
	doc.Registration.ApprovalMode = mode
	if err := peers.Save(opts.peers, doc); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approval mode %s; restart tyd up to apply\n", mode)
	fmt.Println(mode)
	return nil
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

	if state, err := peerstate.Load(opts.peers); err == nil {
		if _, err := ensureCPRegistration(opts, state); err != nil {
			return fmt.Errorf("invite: restore CP registration: %w (or: tyd register --force)", err)
		}
	}
	inv, err := cli.CreateInvite(doc.Registration.ID, pub)
	if err != nil {
		if cpNotFound(err) {
			return fmt.Errorf("invite: daemon not on Control Panel (%w); try: tyd register --force", err)
		}
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
	// The Control Panel mints the invite id and nothing more. The other half of
	// the token is generated here and never sent anywhere, so the Control Panel
	// cannot use it to stand in for this host during accept.
	tok, secret, err := newPairingToken(inv.Token, key)
	if err != nil {
		return err
	}
	printInviteResult(os.Stderr, os.Stdout, inviteResult{
		Kind:      "invite",
		URL:       url,
		Approval:  doc.Registration.ApprovalMode,
		Platform:  cli.BaseURL,
		Relay:     relayURL(opts),
		Token:     tok,
		TTL:       controlpanel.InviteTTL,
		ExpiresAt: inv.ExpiresAt,
	})
	return waitForInviteAccept(opts, cli, key, doc.Registration.ID, pub, tok, secret, inv.Token, inv.ExpiresAt, baseline)
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
//	relay …                 (optional)
//	<blank>
//	Copy and run on the peer:
//	  tyd accept …
//
// From the line after the accept command, move up to rewrite the ttl row.
func inviteTTLCursorOffsets(showRelay bool) (up, down int) {

	below := 3
	if showRelay {
		below++
	}
	return below + 1, below
}

func rewriteInviteTTL(expiresAt time.Time, color bool, desc string, showRelay bool) {
	if desc == "" {
		desc = formatRemaining(time.Until(expiresAt))
	}
	up, down := inviteTTLCursorOffsets(showRelay)
	fmt.Fprintf(os.Stderr, "\033[%dA\r\033[K", up)
	writeHelpRows(os.Stderr, []helpRow{{"invite ttl", desc}}, color)
	fmt.Fprintf(os.Stderr, "\033[%dB", down)
}

// waitForInviteAccept keeps the process alive until a peer accepts the invite,
// the TTL expires, or the user cancels (Ctrl-C revokes the invite).
// On a TTY, the "invite ttl" help row is refreshed in place.
func waitForInviteAccept(opts options, cli *cpclient.Client, key ed25519.PrivateKey, daemonID, pub, token string, secret []byte, inviteID string, expiresAt time.Time, baseline map[string]struct{}) error {
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
	rurl := relayURL(opts)
	showRelay := rurl != "" && rurl != "off"

	for {
		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			if tty {
				rewriteInviteTTL(expiresAt, color, "expired", showRelay)
			}
			return fmt.Errorf("invite expired")
		}
		select {
		case <-sig:
			if err := cli.RevokeInvite(inviteID, daemonID, pub); err != nil {
				return fmt.Errorf("invite cancelled (revoke failed: %v)", err)
			}
			return fmt.Errorf("invite revoked")
		case <-ticker.C:
			if tty {
				rewriteInviteTTL(expiresAt, color, "", showRelay)
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
				// A peer appearing on the Control Panel proves nothing: it is
				// the Control Panel saying so. Only a pairing record this host
				// can check against its own secret is a pairing.
				if err := acceptPairedPeer(opts, key, p, secret, inviteID); err != nil {
					fmt.Fprintf(os.Stderr, "refused %s: %v\n", p.ID, err)
					continue
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

// runRevoke withdraws a pairing. It is the only command that takes a peer's
// access away, so it says what it is about to do and refuses without --force.
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
	owned, err := sessionIDsForPeer(opts, p.ID)
	if err != nil {
		return err
	}
	if !opts.force {
		return fmt.Errorf(`%w
  refusing to revoke peer %s%s
  the peer loses access to this host now, and this host loses the ability to dial it
  %s removed with it, and the pairing cannot be restored without pairing again
  re-run with --force to revoke`, errForceRequired, p.ID, peerSuffix(p), pluralSessions(len(owned)))
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
		// The Control Panel goes first: it is the half that cannot be redone
		// locally, and a local file that outlives a failed revoke would be a
		// peer this host still trusts and the peer no longer expects.
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
	// paired.json is the trust store, and peers.json is not: leaving the entry
	// there would keep the peer trusted until the next sync happened to notice.
	// The daemon prunes it that way, which makes the withdrawal lag a round.
	paired, err := peers.LoadPaired(pairedPath(opts))
	if err != nil {
		return err
	}
	if paired.Remove(p.ID) {
		if err := peers.SavePaired(pairedPath(opts), paired); err != nil {
			return err
		}
	}
	// Sessions reached through the pairing go with it. A row left behind would
	// name a peer this host can no longer dial, and its alias would merge the
	// row straight back.
	if err := forgetSessions(opts, owned); err != nil {
		return err
	}
	if err := archive.Update(archivePath(opts), func(f *archive.File) bool {
		return f.ForgetPeer(p.ID)
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "revoked peer %s\n", p.ID)
	if !colorEnabled(os.Stdout) || !colorEnabled(os.Stderr) {
		fmt.Println(p.ID)
	}
	return nil
}

func peerSuffix(p *peers.Peer) string {
	if p.Nickname == "" {
		return ""
	}
	return fmt.Sprintf(" (%s)", p.Nickname)
}

func pluralSessions(n int) string {
	if n == 1 {
		return "1 local session record is"
	}
	return fmt.Sprintf("%d local session records are", n)
}

// sessionIDsForPeer lists the catalog rows a peer owns, for the risk text and
// for the removal that follows it.
func sessionIDsForPeer(opts options, peerID string) ([]string, error) {
	cat, err := catalog.Load(sessionsPath(opts))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, rec := range cat.Sessions {
		if rec.PeerID == peerID {
			ids = append(ids, rec.ID)
		}
	}
	return ids, nil
}

func runAccept(opts options) error {
	if len(opts.rest) != 1 {
		return fmt.Errorf("usage: tyd accept <invite-token> [--as nickname]")
	}
	// Checked before the Control Panel is told anything, so a reserved nickname
	// cannot reach the pairing record and then have to be unpicked.
	if opts.as != "" {
		if err := peers.ValidateNickname(opts.as); err != nil {
			return fmt.Errorf("accept --as: %w", err)
		}
	}
	// Accept takes either the bare token or the whole pasted line, which is
	// what the inviter printed and what the install script hands over.
	raw := parseInviteToken(opts.rest[0])
	if raw == "" {
		return fmt.Errorf("usage: tyd accept <invite-token> [--as nickname]")
	}
	// The token is <invite-id>.<secret>.<inviter-hash>. Only the id goes to the
	// Control Panel; the secret half is what makes the pairing verifiable by
	// this daemon instead of by the Control Panel.
	tok, err := auth.ParseInviteToken(raw)
	if err != nil {
		return fmt.Errorf("accept: %w (ask the host that invited you for a fresh token)", err)
	}
	key, err := ensureIdentity(opts)
	if err != nil {
		return err
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))
	cli := cpclient.New(opts.platform)
	acc, err := cli.Accept(tok.InviteID, pub, opts.as)
	if err != nil {
		return err
	}

	// The Control Panel just told us who the inviter is. Check it against the
	// hash the inviter put in the token the operator carried over: a Control
	// Panel that substituted its own key is caught here and nowhere else.
	inviter, err := auth.DecodePublic(acc.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("accept: Control Panel returned an unusable inviter key: %w", err)
	}
	if !tok.MatchesInviter(inviter) {
		return fmt.Errorf("accept: the inviter key from the Control Panel does not match the invite token; " +
			"the Control Panel may be substituting it -- stop and pair over a channel you trust")
	}

	// Record the pairing locally, and hand the inviter the half it needs to
	// check the same thing from its side.
	acceptor := key.Public().(ed25519.PublicKey)
	proof := auth.NewPairingProof(tok.InviteID, inviter, acceptor)
	if err := proof.SignAcceptor(key, tok.Secret); err != nil {
		return fmt.Errorf("accept: pairing record: %w", err)
	}
	if err := cli.SubmitAcceptProof(cpclient.AcceptProof{
		InviteID:    tok.InviteID,
		PublicKey:   pub,
		AcceptorSig: auth.EncodeBytes(proof.AcceptorSig),
		AcceptorMAC: auth.EncodeBytes(proof.AcceptorMAC),
		InviterPub:  acc.PeerPublicKey,
	}); err != nil {
		// The pairing itself succeeded; the inviter will refuse to trust us
		// until it can check the proof, so say so rather than failing silently.
		return fmt.Errorf("accept: paired on the Control Panel but the pairing record was rejected (%v); "+
			"this host will not be trusted until the pairing is redone", err)
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
	if err := recordPairing(opts, peers.PairedPeer{
		ID:        acc.PeerID,
		PublicKey: acc.PeerPublicKey,
		Nickname:  acc.PeerNickname,
		Direction: "outbound",
		PairedAt:  time.Now().UTC(),
		Proof:     proof,
	}); err != nil {
		return err
	}
	printAcceptResult(os.Stderr, os.Stdout, acc, peerHasLiveEndpoint(cli, acc.PeerID))
	return nil
}

// newPairingToken turns the Control Panel's invite id into the token the
// operator carries to the other machine, and returns the secret so the inviter
// can check the acceptor's half afterwards.
func newPairingToken(inviteID string, key ed25519.PrivateKey) (string, []byte, error) {
	secret, err := auth.NewInviteSecret()
	if err != nil {
		return "", nil, err
	}
	tok, err := auth.FormatInviteToken(inviteID, secret, key.Public().(ed25519.PublicKey))
	if err != nil {
		return "", nil, err
	}
	return tok.String(), secret, nil
}

// pairedPathFor keeps the pairing record beside peers.json, so pointing --peers
// at a test directory does not write trust records into the real ~/.tyd.
func pairedPathFor(peersPath string) string {
	if strings.TrimSpace(peersPath) == "" {
		return paths.Paired()
	}
	return strings.TrimSuffix(peersPath, ".json") + "-paired.json"
}

// acceptPairedPeer checks a new peer against the secret this host minted and,
// only then, records the pairing. A peer the Control Panel lists without a
// checkable record is refused: that is the shape a Control Panel uses to
// introduce a key it holds.
func acceptPairedPeer(opts options, key ed25519.PrivateKey, p controlpanel.Peer, secret []byte, inviteID string) error {
	if p.Proof == nil {
		return fmt.Errorf("no pairing record; the Control Panel listed this peer but the other host did not prove it holds the invite secret -- upgrade it and pair again")
	}
	acceptorPub, err := auth.DecodePublic(p.PublicKey)
	if err != nil {
		return fmt.Errorf("unusable peer key: %w", err)
	}
	inviterPub, err := auth.DecodePublic(p.Proof.InviterPub)
	if err != nil {
		return fmt.Errorf("pairing record names an unusable inviter key: %w", err)
	}
	// The record must name this host as the inviter, or it is a record lifted
	// from some other pairing.
	if !inviterPub.Equal(key.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("pairing record is for a different inviter")
	}
	sig, err := auth.DecodeBytes(p.Proof.AcceptorSig)
	if err != nil {
		return fmt.Errorf("pairing record signature is unreadable: %w", err)
	}
	mac, err := auth.DecodeBytes(p.Proof.AcceptorMAC)
	if err != nil {
		return fmt.Errorf("pairing record mac is unreadable: %w", err)
	}
	proof := &auth.PairingProof{
		Version:     auth.PairingProofVersion,
		InviteID:    inviteID,
		Inviter:     inviterPub,
		Acceptor:    acceptorPub,
		AcceptorSig: sig,
		AcceptorMAC: mac,
		PairedAt:    p.PairedAt,
	}
	if err := proof.VerifyAcceptor(secret); err != nil {
		return fmt.Errorf("%w; the Control Panel may be substituting this peer", err)
	}
	if err := proof.Countersign(key); err != nil {
		return err
	}
	if !proof.Verified() {
		return fmt.Errorf("pairing record did not verify after countersigning")
	}
	return recordPairing(opts, peers.PairedPeer{
		ID:        p.ID,
		PublicKey: p.PublicKey,
		Nickname:  p.Nickname,
		Direction: "inbound",
		PairedAt:  p.PairedAt,
		Proof:     proof,
	})
}

// recordPairing writes the local trust record. This file, not peers.json, is
// what the daemon trusts from: peers.json is rebuilt from the Control Panel on
// every sync, so anything in it is a peer the Control Panel asked for.
func recordPairing(opts options, p peers.PairedPeer) error {
	path := opts.paired
	if path == "" {
		path = pairedPathFor(opts.peers)
	}
	f, err := peers.LoadPaired(path)
	if err != nil {
		return err
	}
	f.Upsert(p)
	return peers.SavePaired(path, f)
}

func peerHasLiveEndpoint(cli *cpclient.Client, peerID string) bool {
	if cli == nil || peerID == "" {
		return false
	}
	_, err := cli.GetEndpointFull(peerID)
	return err == nil
}

func sessionCreateCommand(peerID, nickname string) string {
	target := nickname
	if target == "" {
		target = peerID
	}
	if target == "" {
		return ""
	}
	return "tyd session create --peer " + target
}

func printAcceptResult(errW, outW io.Writer, acc *controlpanel.AcceptResponse, live bool) {
	if acc.AlreadyPaired {
		label := acc.PeerID
		if acc.PeerNickname != "" {
			label = fmt.Sprintf("%s (%s)", acc.PeerID, acc.PeerNickname)
		}
		fmt.Fprintf(errW, "already paired with %s\n", label)
	} else {
		fmt.Fprintf(errW, "paired with %s\n", acc.PeerID)
	}
	if live {
		cmd := sessionCreateCommand(acc.PeerID, acc.PeerNickname)
		if cmd != "" {
			fmt.Fprintln(errW)
			fmt.Fprintln(errW, "Connect with:")
			if colorEnabled(errW) {
				fmt.Fprintf(errW, "  %s%s%s\n", ansiCyan, cmd, ansiReset)
			} else {
				fmt.Fprintf(errW, "  %s\n", cmd)
			}
		}
	}
	if !colorEnabled(outW) || !colorEnabled(errW) {
		fmt.Fprintln(outW, acc.PeerID)
	}
}

type inviteResult struct {
	Kind      string // registered | invite
	URL       string
	Approval  string
	Platform  string
	Relay     string
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
	rows := make([]helpRow, 0, 4)
	if r.URL != "" {
		rows = append(rows, helpRow{"url", r.URL})
	}
	if r.Approval != "" {
		rows = append(rows, helpRow{"approval", r.Approval})
	}
	rows = append(rows, helpRow{"invite ttl", ttl})
	if r.Relay != "" && r.Relay != "off" {
		rows = append(rows, helpRow{"relay", r.Relay + " (offers on tyd up)"})
	} else if r.Relay == "off" {
		rows = append(rows, helpRow{"relay", "off"})
	}
	writeHelpRows(errW, rows, color)
	fmt.Fprintln(errW)
	fmt.Fprintln(errW, "Copy and run on the peer:")
	cmd := formatAcceptCommand(r.Platform, r.Token)
	if color {
		fmt.Fprintf(errW, "  %s%s%s\n", ansiCyan, cmd, ansiReset)
	} else {
		fmt.Fprintf(errW, "  %s\n", cmd)
	}

	if !colorEnabled(outW) || !colorEnabled(errW) {
		fmt.Fprintln(outW, cmd)
	}
}
