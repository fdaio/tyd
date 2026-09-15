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
