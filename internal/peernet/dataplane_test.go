package peernet_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/controlpanel"
	"tyd/internal/cpclient"
	"tyd/internal/peers"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// TestDataPlanePeerSession: CP signaling + peer AuthN + direct QUIC session create
// (client list is local-catalog and is not exercised here).
func TestDataPlanePeerSession(t *testing.T) {
	svc := controlpanel.New()
	cpAddr, cpSrv, err := controlpanel.ListenAndServe("127.0.0.1:0", svc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cpSrv.Close() })
	platform := "http://" + cpAddr.String()
	cp := cpclient.New(platform)
	cp.HTTPClient.Timeout = 3 * time.Second

	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	clientDir := filepath.Join(root, "client")
	_ = os.MkdirAll(serverDir, 0o700)
	_ = os.MkdirAll(clientDir, 0o700)

	sKey, _, err := auth.EnsureIdentity(filepath.Join(serverDir, "id"), filepath.Join(serverDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	cKey, _, err := auth.EnsureIdentity(filepath.Join(clientDir, "id"), filepath.Join(clientDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	sPub := auth.EncodePublic(sKey.Public().(ed25519.PublicKey))
	cPub := auth.EncodePublic(cKey.Public().(ed25519.PublicKey))

	reg, err := cp.Register(sPub, controlpanel.ApprovalFull)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := cp.CreateInvite(reg.ID, sPub)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := cp.Accept(inv.Token, cPub, "box")
	if err != nil {
		t.Fatal(err)
	}

	sPeersPath := filepath.Join(serverDir, "peers.json")
	cPeersPath := filepath.Join(clientDir, "peers.json")
	sDoc := &peers.File{
		Platform: platform,
		Registration: &peers.Registration{
			ID:           reg.ID,
			PublicKey:    sPub,
			ApprovalMode: controlpanel.ApprovalFull,
			RegisteredAt: time.Now().UTC(),
		},
	}
	remote, err := cp.ListPeers(reg.ID, sPub)
	if err != nil {
		t.Fatal(err)
	}
	sDoc.MergePeers(toLocal(remote))
	if err := peers.Save(sPeersPath, sDoc); err != nil {
		t.Fatal(err)
	}
	cDoc := &peers.File{
		Platform: platform,
		Registration: &peers.Registration{
			ID:           acc.SelfID,
			PublicKey:    cPub,
			ApprovalMode: controlpanel.ApprovalFull,
			RegisteredAt: time.Now().UTC(),
		},
	}
	cDoc.UpsertPeer(peers.Peer{
		ID:        acc.PeerID,
		PublicKey: acc.PeerPublicKey,
		Nickname:  acc.PeerNickname,
		Direction: "outbound",
		PairedAt:  time.Now().UTC(),
	})
	if err := peers.Save(cPeersPath, cDoc); err != nil {
		t.Fatal(err)
	}

	trust, err := auth.LoadStore(filepath.Join(serverDir, "trusted.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sDoc.Peers {
		pub, err := auth.DecodePublic(p.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		name := p.Nickname
		if name == "" {
			name = p.ID
		}
		trust.EnsurePeer(name, pub, auth.AllGlobal)
	}

	sock := filepath.Join(serverDir, "tyd.sock")
	cert := filepath.Join(serverDir, "server.crt")
	keyPath := filepath.Join(serverDir, "server.key")
	srv := server.NewWithConfig(server.Config{
		Socket:     sock,
		Listen:     "off",
		DataListen: "127.0.0.1:0",
		CertPath:   cert,
		KeyPath:    keyPath,
		Mgr:        session.NewManager(),
		Trust:      trust,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	dp := srv.DataPlaneAddr()
	if dp == "" {
		t.Fatal("missing data-plane addr")
	}
	fp := srv.TLSFingerprintFull()
	// The fixture binds loopback, so loopback is all it may publish.
	// transport.ExpandCandidates would append every non-loopback interface address
	// on the host, so the candidate list would be whatever network this machine
	// happens to have — on the box that found this, a Tailscale address and three
	// LAN addresses. A test about the dataplane should not depend on that, and
	// should not report a dial failure against an address nothing is listening on.
	//
	// This is a hygiene fix and not the cause of the reported failures: with the
	// host addresses removed, a loopback-only dial still times out under the same
	// load, because the QUIC handshake exceeds quic-go's 5s default idle timeout
	// when the machine is oversubscribed. See #135.
	cands := []string{dp}
	// Signed the way a daemon signs it, so the client that dials this endpoint
	// can check it against the key it pinned at pairing.
	record := auth.NewEndpointRecord(reg.ID, sPub, dp, fp, "quic", cands,
		time.Now(), controlpanel.DefaultEndpointTTL, 1)
	sig, err := record.Sign(sKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.PublishEndpointFull(reg.ID, controlpanel.PublishEndpointRequest{
		PublicKey:  sPub,
		Addr:       dp,
		CertFP:     fp,
		Transport:  "quic",
		Candidates: cands,
		TTLSeconds: int(controlpanel.DefaultEndpointTTL / time.Second),
		Proof: &controlpanel.EndpointProof{
			Record: record,
			Sig:    auth.EncodeBytes(sig),
		},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := cp.GetEndpointFull(reg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != dp || got.CertFP != fp || got.Transport != "quic" {
		t.Fatalf("endpoint %+v want addr=%s fp=%s quic", got, dp, fp)
	}
	if len(got.Candidates) == 0 {
		t.Fatal("expected candidates")
	}

	ep := client.Endpoint{
		Kind:       transport.KindQUIC,
		Address:    got.Addr,
		CertFP:     got.CertFP,
		Candidates: got.Candidates,
	}
	if err := client.WaitReady(ep, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	info, err := client.Create(ep, cKey, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" {
		t.Fatal("empty session")
	}
	listed, err := client.List(ep, cKey)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range listed {
		if it.ID == info.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("session %s not listed: %+v", info.ID, listed)
	}
	_ = client.CloseSession(ep, cKey, info.ID)

	if err := cp.RevokePeer(reg.ID, sPub, acc.SelfID); err != nil {
		t.Fatal(err)
	}
	remote, err = cp.ListPeers(reg.ID, sPub)
	if err != nil {
		t.Fatal(err)
	}
	sDoc.ReplaceFromRemote(toLocal(remote))
	var keep []ed25519.PublicKey
	for _, p := range sDoc.Peers {
		pub, err := auth.DecodePublic(p.PublicKey)
		if err != nil {
			continue
		}
		keep = append(keep, pub)
	}
	trust.DropUnlistedPeers(keep)
	if _, err := client.Create(ep, cKey, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()}); err == nil {
		t.Fatal("expected create to fail after peer revoke")
	}
}

func toLocal(list []controlpanel.Peer) []peers.Peer {
	out := make([]peers.Peer, 0, len(list))
	for _, p := range list {
		out = append(out, peers.Peer{
			ID: p.ID, PublicKey: p.PublicKey, Nickname: p.Nickname,
			Direction: p.Direction, PairedAt: p.PairedAt,
		})
	}
	return out
}

func TestDialTLSFingerprintRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	ln, fp, err := transport.ListenTLS("127.0.0.1:0", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			_, _ = c.Read(buf) // complete handshake / keep open briefly
			_ = c.Close()
		}
	}()
	c, err := transport.DialTLSFingerprint(ln.Addr().String(), fp)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	wrong := otherFingerprint(fp)
	if wrong == fp {
		t.Fatalf("test is vacuous: the wrong fingerprint equals the real one (%s)", fp)
	}
	if _, err := transport.DialTLSFingerprint(ln.Addr().String(), wrong); err == nil {
		t.Fatal("expected fingerprint mismatch")
	}
}

// otherFingerprint returns a fingerprint that is guaranteed to differ from
// fp. Prefixing a fixed pair is not enough: with a real fingerprint that
// happens to start "00", the "wrong" value is the right one and the test
// fails for the wrong reason, roughly once every 256 runs.
func otherFingerprint(fp string) string {
	flipped := '0'
	if fp[0] == '0' {
		flipped = '1'
	}
	return string(flipped) + fp[1:]
}

// The old assertion broke once every 256 runs, because the "mismatched"
// fingerprint it built was the real one. Pin the case directly.
func TestOtherFingerprintAlwaysDiffers(t *testing.T) {
	cases := map[string]string{
		// The exact shape that defeated the old test: a real fingerprint
		// starting "00" is its own "mismatch".
		"00abcdef0123456789": "10abcdef0123456789",
		"0fabcdef0123456789": "1fabcdef0123456789",
		"ffabcdef0123456789": "0fabcdef0123456789",
		"3a":                 "0a",
	}
	for fp, want := range cases {
		if got := otherFingerprint(fp); got != want {
			t.Errorf("otherFingerprint(%q) = %q, want %q", fp, got, want)
		}
	}
	// And it must never return its input, whatever the prefix.
	for _, fp := range []string{"00", "0", "ff", "a0", "0000"} {
		if got := otherFingerprint(fp); got == fp {
			t.Errorf("otherFingerprint(%q) returned the input", fp)
		}
	}
}
