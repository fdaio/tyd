package controlpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestEndpointPublishFetchExpire(t *testing.T) {
	s := New()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	s.SetNow(func() time.Time { return now })

	reg, err := s.Register(RegisterRequest{PublicKey: "pk-ep"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEndpoint(reg.ID); err != ErrNotFound {
		t.Fatalf("want not found, got %v", err)
	}

	pub, err := s.PublishEndpoint(reg.ID, PublishEndpointRequest{
		PublicKey:  "pk-ep",
		Addr:       "127.0.0.1:61211",
		CertFP:     "abcd",
		TTLSeconds: 60,
	})
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
	if _, err := s.PublishEndpoint(reg.ID, PublishEndpointRequest{
		PublicKey: "pk-ep", Addr: "127.0.0.1:9", CertFP: "ef01",
	}); err != nil {
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

	regBody, _ := json.Marshal(RegisterRequest{PublicKey: "http-ep"})
	res, err := http.Post(ts.URL+"/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var reg RegisterResponse
	_ = json.NewDecoder(res.Body).Decode(&reg)
	_ = res.Body.Close()

	body, _ := json.Marshal(PublishEndpointRequest{
		PublicKey: "http-ep", Addr: "127.0.0.1:1", CertFP: "aa",
	})
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
