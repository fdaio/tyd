package controlpanel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
)

func TestRegisterAllocateIDAndDefaultApproval(t *testing.T) {
	s := New()
	resp, err := s.Register(RegisterRequest{PublicKey: "pk-server"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID == "" || resp.ApprovalMode != ApprovalFull {
		t.Fatalf("%+v", resp)
	}
	again, err := s.Register(RegisterRequest{PublicKey: "pk-server", ApprovalMode: ApprovalPre})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != resp.ID {
		t.Fatalf("expected stable id, got %s vs %s", again.ID, resp.ID)
	}
	if again.ApprovalMode != ApprovalPre {
		t.Fatalf("approval=%s", again.ApprovalMode)
	}
}

func TestInviteExpiry(t *testing.T) {
	s := New()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })

	reg, err := s.Register(RegisterRequest{PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	if !inv.ExpiresAt.Equal(now.Add(InviteTTL)) {
		t.Fatalf("expires %v", inv.ExpiresAt)
	}

	// Still valid just before expiry.
	s.SetNow(func() time.Time { return now.Add(InviteTTL - time.Second) })
	if _, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "pk-c"}); err != nil {
		t.Fatalf("expected accept before expiry: %v", err)
	}

	// Fresh invite at original clock, then expire.
	s.SetNow(func() time.Time { return now })
	inv2, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetNow(func() time.Time { return now.Add(InviteTTL) })
	_, err = s.Accept(AcceptRequest{Token: inv2.Token, PublicKey: "pk-c2"})
	if err != ErrInviteExpired {
		t.Fatalf("want ErrInviteExpired, got %v", err)
	}
}

func TestAcceptExchangesPeerKeys(t *testing.T) {
	s := New()
	sReg, err := s.Register(RegisterRequest{PublicKey: "server-pub", ApprovalMode: ApprovalPost})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: sReg.ID, PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "client-pub", Nickname: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if acc.PeerID != sReg.ID || acc.PeerPublicKey != "server-pub" {
		t.Fatalf("peer %+v", acc)
	}
	if acc.SelfPublicKey != "client-pub" || acc.SelfID == "" {
		t.Fatalf("self %+v", acc)
	}
	if acc.PeerNickname != "work" {
		t.Fatalf("nick %q", acc.PeerNickname)
	}

	serverPeers, err := s.ListPeers(sReg.ID, "server-pub")
	if err != nil {
		t.Fatal(err)
	}
	if len(serverPeers) != 1 || serverPeers[0].PublicKey != "client-pub" || serverPeers[0].Direction != "inbound" {
		t.Fatalf("server peers %+v", serverPeers)
	}
	clientPeers, err := s.ListPeers(acc.SelfID, "client-pub")
	if err != nil {
		t.Fatal(err)
	}
	if len(clientPeers) != 1 || clientPeers[0].PublicKey != "server-pub" || clientPeers[0].Nickname != "work" {
		t.Fatalf("client peers %+v", clientPeers)
	}
}

func TestAcceptAlreadyPairedReturnsExistingPeer(t *testing.T) {
	s := New()
	sReg, err := s.Register(RegisterRequest{PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: sReg.ID, PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "client-pub", Nickname: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if first.AlreadyPaired {
		t.Fatal("first accept should create the pair")
	}

	inv2, err := s.CreateInvite(CreateInviteRequest{DaemonID: sReg.ID, PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Accept(AcceptRequest{Token: inv2.Token, PublicKey: "client-pub", Nickname: "other"})
	if err != nil {
		t.Fatalf("already paired should not error: %v", err)
	}
	if !again.AlreadyPaired || again.PeerID != sReg.ID || again.PeerPublicKey != "server-pub" {
		t.Fatalf("again %+v", again)
	}
	if again.SelfID != first.SelfID || again.PeerNickname != "laptop" {
		t.Fatalf("nickname/id changed: %+v", again)
	}
	peers, err := s.ListPeers(sReg.ID, "server-pub")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("duplicate pair: %+v", peers)
	}
	// The retried invite stays usable for a different client.
	other, err := s.Accept(AcceptRequest{Token: inv2.Token, PublicKey: "client-pub-2"})
	if err != nil || other.AlreadyPaired || other.PeerID != sReg.ID {
		t.Fatalf("invite should still be open, got %+v %v", other, err)
	}
}

func TestEndpointPublishFetchExpire(t *testing.T) {
	s := New()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })

	epPub, epPriv := testKeyPair(t)
	reg, err := s.Register(RegisterRequest{PublicKey: auth.EncodePublic(epPub)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEndpoint(reg.ID); err != ErrNotFound {
		t.Fatalf("want not found, got %v", err)
	}

	pub, err := s.PublishEndpoint(reg.ID, signedEndpoint(t, reg.ID, epPub, epPriv, "127.0.0.1:61211", "abcd", now, 60, 1))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Addr != "127.0.0.1:61211" || pub.CertFP != "abcd" {
		t.Fatalf("%+v", pub)
	}
	got, err := s.GetEndpoint(reg.ID)
	if err != nil || got.Addr != pub.Addr || got.CertFP != pub.CertFP {
		t.Fatalf("got %+v err %v", got, err)
	}

	// Overwrite on republish.
	if _, err := s.PublishEndpoint(reg.ID, signedEndpoint(t, reg.ID, epPub, epPriv, "127.0.0.1:9", "ef01", now, 60, 2)); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetEndpoint(reg.ID)
	if err != nil || got.Addr != "127.0.0.1:9" || got.CertFP != "ef01" {
		t.Fatalf("overwrite %+v %v", got, err)
	}

	if _, err := s.PublishEndpoint(reg.ID, PublishEndpointRequest{
		PublicKey: "wrong", Addr: "x", CertFP: "y",
	}); err != ErrUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}

	s.SetNow(func() time.Time { return now.Add(DefaultEndpointTTL) })
	if _, err := s.GetEndpoint(reg.ID); err != ErrNotFound {
		t.Fatalf("want expired not found, got %v", err)
	}
}

func TestHTTPEndpoint(t *testing.T) {
	s := New()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	httpPub, httpPriv := testKeyPair(t)
	regBody, _ := json.Marshal(RegisterRequest{PublicKey: auth.EncodePublic(httpPub)})
	res, err := http.Post(ts.URL+"/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var reg RegisterResponse
	_ = json.NewDecoder(res.Body).Decode(&reg)
	_ = res.Body.Close()

	body, _ := json.Marshal(signedEndpoint(t, reg.ID, httpPub, httpPriv, "127.0.0.1:1", "aa", time.Now(), 60, 1))
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/daemons/"+reg.ID+"/endpoint", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res2.StatusCode)
	}

	res3, err := http.Get(ts.URL + "/v1/daemons/" + reg.ID + "/endpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	var ep EndpointResponse
	if err := json.NewDecoder(res3.Body).Decode(&ep); err != nil {
		t.Fatal(err)
	}
	if ep.Addr != "127.0.0.1:1" || ep.CertFP != "aa" {
		t.Fatalf("%+v", ep)
	}
}

func TestHTTPRegisterAcceptFlow(t *testing.T) {
	s := New()
	s.SetBaseURL("http://cp.test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	regBody, _ := json.Marshal(RegisterRequest{PublicKey: "http-s"})
	res, err := http.Post(ts.URL+"/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var reg RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.URL != "http://cp.test/"+reg.ID {
		t.Fatalf("url %q", reg.URL)
	}

	invBody, _ := json.Marshal(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "http-s"})
	res2, err := http.Post(ts.URL+"/v1/invites", "application/json", bytes.NewReader(invBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var inv CreateInviteResponse
	if err := json.NewDecoder(res2.Body).Decode(&inv); err != nil {
		t.Fatal(err)
	}

	accBody, _ := json.Marshal(AcceptRequest{Token: inv.Token, PublicKey: "http-c"})
	res3, err := http.Post(ts.URL+"/v1/accept", "application/json", bytes.NewReader(accBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res3.Body.Close()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res3.StatusCode)
	}
	var acc AcceptResponse
	if err := json.NewDecoder(res3.Body).Decode(&acc); err != nil {
		t.Fatal(err)
	}
	if acc.PeerPublicKey != "http-s" {
		t.Fatalf("%+v", acc)
	}
}

func TestRevokeInviteBlocksAccept(t *testing.T) {
	s := New()
	reg, err := s.Register(RegisterRequest{PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeInvite(RevokeInviteRequest{Token: inv.Token, DaemonID: "nope", PublicKey: "pk-s"}); err != ErrUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if err := s.RevokeInvite(RevokeInviteRequest{Token: inv.Token, DaemonID: reg.ID, PublicKey: "pk-s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "pk-c"}); err != ErrNotFound {
		t.Fatalf("want not found after revoke, got %v", err)
	}
}

func TestRevokePeerRemovesBothSides(t *testing.T) {
	s := New()
	sReg, err := s.Register(RegisterRequest{PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: sReg.ID, PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "client-pub", Nickname: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePeer(sReg.ID, "server-pub", acc.SelfID); err != nil {
		t.Fatal(err)
	}
	sp, err := s.ListPeers(sReg.ID, "server-pub")
	if err != nil {
		t.Fatal(err)
	}
	if len(sp) != 0 {
		t.Fatalf("server still has peers %+v", sp)
	}
	cp, err := s.ListPeers(acc.SelfID, "client-pub")
	if err != nil {
		t.Fatal(err)
	}
	if len(cp) != 0 {
		t.Fatalf("client still has peers %+v", cp)
	}
	if err := s.RevokePeer(sReg.ID, "server-pub", acc.SelfID); err != ErrNotPaired {
		t.Fatalf("want not paired, got %v", err)
	}

	inv2, err := s.CreateInvite(CreateInviteRequest{DaemonID: sReg.ID, PublicKey: "server-pub"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(AcceptRequest{Token: inv2.Token, PublicKey: "client-pub"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokePeer(acc.SelfID, "client-pub", sReg.ID); err != nil {
		t.Fatal(err)
	}
	sp, _ = s.ListPeers(sReg.ID, "server-pub")
	if len(sp) != 0 {
		t.Fatalf("after client revoke %+v", sp)
	}
}

func TestAcceptOwnInviteRejected(t *testing.T) {
	s := New()
	reg, err := s.Register(RegisterRequest{PublicKey: "same"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "same"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "same"}); err == nil {
		t.Fatal("expected cannot accept own invite")
	}
}

func TestRegisterForceReplacesIDAndDropsPeers(t *testing.T) {
	s := New()
	reg, err := s.Register(RegisterRequest{PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "pk-c"}); err != nil {
		t.Fatal(err)
	}
	peers, err := s.ListPeers(reg.ID, "pk-s")
	if err != nil || len(peers) != 1 {
		t.Fatalf("peers before force: %v %v", peers, err)
	}
	again, err := s.Register(RegisterRequest{PublicKey: "pk-s", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == reg.ID {
		t.Fatalf("expected new id after force, got %s", again.ID)
	}
	peers, err = s.ListPeers(again.ID, "pk-s")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected no peers after force, got %+v", peers)
	}
	if _, err := s.GetDaemon(reg.ID); err != ErrNotFound {
		t.Fatalf("old daemon should be gone: %v", err)
	}
}

func TestRestoreRehydratesIDAndPeers(t *testing.T) {
	s := New()
	reg, err := s.Register(RegisterRequest{PublicKey: "pk-s", ApprovalMode: ApprovalPre})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := s.CreateInvite(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "pk-s"})
	if err != nil {
		t.Fatal(err)
	}
	acc, err := s.Accept(AcceptRequest{Token: inv.Token, PublicKey: "pk-c", Nickname: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	peers, err := s.ListPeers(reg.ID, "pk-s")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate CP restart: empty service, restore from local snapshot.
	s2 := New()
	resp, err := s2.Restore(RestoreRequest{
		ID:           reg.ID,
		PublicKey:    "pk-s",
		ApprovalMode: ApprovalPre,
		Peers:        peers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID != reg.ID || resp.ApprovalMode != ApprovalPre {
		t.Fatalf("%+v", resp)
	}
	got, err := s2.ListPeers(reg.ID, "pk-s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != acc.SelfID || got[0].PublicKey != "pk-c" {
		t.Fatalf("%+v", got)
	}
	clientPeers, err := s2.ListPeers(acc.SelfID, "pk-c")
	if err != nil {
		t.Fatal(err)
	}
	if len(clientPeers) != 1 || clientPeers[0].ID != reg.ID {
		t.Fatalf("reciprocal missing: %+v", clientPeers)
	}
}

func TestHTTPRestore(t *testing.T) {
	s := New()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	body, _ := json.Marshal(RestoreRequest{
		ID:        "deadbeefcafebabe",
		PublicKey: "pk-restore",
		Peers: []Peer{{
			ID: "peer111122223333", PublicKey: "pk-peer", Direction: "outbound",
		}},
	})
	res, err := http.Post(ts.URL+"/v1/restore", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var out RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "deadbeefcafebabe" {
		t.Fatalf("%+v", out)
	}
}

func TestHTTPRevokePeer(t *testing.T) {
	s := New()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	regBody, _ := json.Marshal(RegisterRequest{PublicKey: "http-s2"})
	res, err := http.Post(ts.URL+"/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var reg RegisterResponse
	_ = json.NewDecoder(res.Body).Decode(&reg)
	_ = res.Body.Close()

	invBody, _ := json.Marshal(CreateInviteRequest{DaemonID: reg.ID, PublicKey: "http-s2"})
	res2, err := http.Post(ts.URL+"/v1/invites", "application/json", bytes.NewReader(invBody))
	if err != nil {
		t.Fatal(err)
	}
	var inv CreateInviteResponse
	_ = json.NewDecoder(res2.Body).Decode(&inv)
	_ = res2.Body.Close()

	accBody, _ := json.Marshal(AcceptRequest{Token: inv.Token, PublicKey: "http-c2"})
	res3, err := http.Post(ts.URL+"/v1/accept", "application/json", bytes.NewReader(accBody))
	if err != nil {
		t.Fatal(err)
	}
	var acc AcceptResponse
	_ = json.NewDecoder(res3.Body).Decode(&acc)
	_ = res3.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/v1/daemons/"+reg.ID+"/peers/"+acc.SelfID+"?public_key=http-s2", nil)
	res4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res4.Body.Close()
	if res4.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res4.StatusCode)
	}
}

func TestInstallScriptHTTP(t *testing.T) {
	s := New()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + "/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	ct := res.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type %q", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("#!/bin/sh")) {
		t.Fatalf("prefix %q", body[:min(40, len(body))])
	}
	if !bytes.Contains(body, []byte("https://app.getfda.dev/install.sh")) {
		t.Fatal("expected production install URL in script")
	}
	// The archive name carries os+arch: one download per platform instead of a
	// per-OS tarball holding every architecture and the relay.
	if !bytes.Contains(body, []byte("https://github.com/fdaio/tyd/releases/latest/download/tyd-${OS}-${ARCH}.tar.gz")) {
		t.Fatal("expected the per-os+arch GitHub Release download path in script")
	}
	if bytes.Contains(body, []byte("/releases/tyd-")) {
		t.Fatal("install script must not download binaries from the Control Panel /releases/")
	}

	req, err := http.NewRequest(http.MethodHead, ts.URL+"/install.sh", nil)
	if err != nil {
		t.Fatal(err)
	}
	head, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status %d", head.StatusCode)
	}

	post, err := http.Post(ts.URL+"/install.sh", "text/plain", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", post.StatusCode)
	}
}

func TestReleaseDirServesArchive(t *testing.T) {
	dir := t.TempDir()
	name := "tyd-linux.tar.gz"
	payload := []byte("fake-tarball")
	if err := os.WriteFile(filepath.Join(dir, name), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	s := New()
	s.SetReleaseDir(dir)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + "/releases/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body %q", body)
	}

	missing, err := http.Get(ts.URL + "/releases/nope.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status %d", missing.StatusCode)
	}

	off := New()
	tsOff := httptest.NewServer(off.Handler())
	t.Cleanup(tsOff.Close)
	resOff, err := http.Get(tsOff.URL + "/releases/" + name)
	if err != nil {
		t.Fatal(err)
	}
	resOff.Body.Close()
	if resOff.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled status %d", resOff.StatusCode)
	}
}

// Recovering a lost peers.json must not relax the approval mode.
func TestRegisterWithoutModeKeepsExisting(t *testing.T) {
	s := New()
	first, err := s.Register(RegisterRequest{PublicKey: "pk-keep", ApprovalMode: ApprovalPre})
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Register(RegisterRequest{PublicKey: "pk-keep"})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID {
		t.Fatalf("id changed %s -> %s", first.ID, again.ID)
	}
	if again.ApprovalMode != ApprovalPre {
		t.Fatalf("approval=%s want pre", again.ApprovalMode)
	}
	// A stated mode still wins.
	changed, err := s.Register(RegisterRequest{PublicKey: "pk-keep", ApprovalMode: ApprovalPost})
	if err != nil {
		t.Fatal(err)
	}
	if changed.ApprovalMode != ApprovalPost {
		t.Fatalf("approval=%s want post", changed.ApprovalMode)
	}
	// A brand new daemon with no stated mode gets the default.
	fresh, err := s.Register(RegisterRequest{PublicKey: "pk-fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ApprovalMode != DefaultApproval {
		t.Fatalf("approval=%s want %s", fresh.ApprovalMode, DefaultApproval)
	}
}

// testKeyPair is a throwaway identity for the endpoint tests.
func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// signedEndpoint builds a publish request the way a daemon does: the record is
// signed with the daemon's own key, and the Control Panel refuses anything it
// cannot check.
func signedEndpoint(t *testing.T, daemonID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, addr, certFP string, publishedAt time.Time, ttlSec int, seq uint64) PublishEndpointRequest {
	t.Helper()
	rec := auth.NewEndpointRecord(daemonID, auth.EncodePublic(pub), addr, certFP, "quic", nil, publishedAt, time.Duration(ttlSec)*time.Second, seq)
	sig, err := rec.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	return PublishEndpointRequest{
		PublicKey:  auth.EncodePublic(pub),
		Addr:       addr,
		CertFP:     certFP,
		Transport:  "quic",
		TTLSeconds: ttlSec,
		Proof:      &EndpointProof{Record: rec, Sig: auth.EncodeBytes(sig)},
	}
}
