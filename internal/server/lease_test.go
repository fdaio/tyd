package server

import (
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/transport"
)

func TestLeaseCoversTerminalOps(t *testing.T) {
	s := NewWithConfig(Config{})
	s.grantLease("sess", "peer", time.Minute)
	for _, op := range []string{opAttach, opWatch, opRead, opSend} {
		if !s.hasLease("sess", "peer", op) {
			t.Errorf("lease did not cover %s", op)
		}
	}
	if s.hasLease("sess", "peer", opCreate) || s.hasLease("sess", "peer", "close") {
		t.Error("lease covered a non-terminal operation")
	}
	if s.hasLease("sess", "other", opRead) {
		t.Error("lease leaked to another principal")
	}
	if s.hasLease("other", "peer", opRead) {
		t.Error("lease leaked to another session")
	}
}

func TestLeaseExpires(t *testing.T) {
	s := NewWithConfig(Config{})
	s.grantLease("sess", "peer", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if s.hasLease("sess", "peer", opRead) {
		t.Fatal("expired lease still allowed a read")
	}
	if _, ok := s.leases[leaseKey("sess", "peer")]; ok {
		t.Fatal("expired lease was not removed")
	}
}

func TestGateAttachAcceptsALeaseWithoutPending(t *testing.T) {
	s := NewWithConfig(Config{ApprovalMode: "pre"})
	st := &connState{
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "10.0.0.2:1"},
		principal: &auth.Principal{Name: "peer"},
	}
	s.grantLease("sess", "peer", time.Minute)
	if err := s.gateAttach(st, "sess", opRead, 0); err != nil {
		t.Fatalf("gated read with a lease: %v", err)
	}
	if len(s.pendingFor("sess")) != 0 {
		t.Fatal("a lease produced a pending request")
	}
}

func TestLeaseListAndRevoke(t *testing.T) {
	s := NewWithConfig(Config{})
	s.grantLease("sess", "peer-a", time.Minute)
	s.grantLease("sess", "peer-b", time.Minute)
	s.grantLease("other", "peer-a", time.Minute)

	got := s.leasesFor("sess")
	if len(got) != 2 {
		t.Fatalf("leasesFor = %+v, want two", got)
	}
	if got[0].Principal != "peer-a" || got[1].Principal != "peer-b" {
		t.Errorf("principals = %q, %q", got[0].Principal, got[1].Principal)
	}
	if len(got[0].Ops) == 0 {
		t.Error("the listing has no operations")
	}

	if n := s.revokeLeases("sess"); n != 2 {
		t.Errorf("revokeLeases = %d, want 2", n)
	}
	if got := s.leasesFor("sess"); len(got) != 0 {
		t.Errorf("leases remain after revoke: %+v", got)
	}
	if got := s.leasesFor("other"); len(got) != 1 {
		t.Error("revoke touched another session")
	}
}

func TestPendingPrincipal(t *testing.T) {
	s := NewWithConfig(Config{})
	s.pending["k"] = &pendingAttach{sessionID: "sess", principal: "peer", digest: "abc"}
	if got := s.pendingPrincipal("sess", "abc"); got != "peer" {
		t.Errorf("pendingPrincipal = %q, want peer", got)
	}
	if got := s.pendingPrincipal("sess", "other"); got != "" {
		t.Errorf("pendingPrincipal for a wrong digest = %q", got)
	}
}
