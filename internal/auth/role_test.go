package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestViewerCanWatchAndReadAnySession(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	s := NewStore()
	p := s.Add("viewer", pub, []Cap{CapList, CapWatchAny, CapReadAny})

	for _, c := range []Cap{CapWatch, CapRead} {
		if !s.Allow(p, c, "any-session") {
			t.Errorf("viewer denied %s", c)
		}
	}
	for _, c := range []Cap{CapAttach, CapWrite, CapResize, CapSignal, CapClose, CapCreate} {
		if s.Allow(p, c, "any-session") {
			t.Errorf("viewer allowed %s", c)
		}
	}
}

func TestSetPeerReplacesGlobalCaps(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	s := NewStore()
	p := s.Add("peer", pub, AllGlobal)
	if !s.Allow(p, CapCreate, "") {
		t.Fatal("setup did not grant create")
	}
	if err := s.Grant(pub, "sess1", CapAttach); err != nil {
		t.Fatal(err)
	}

	s.SetPeer("peer", pub, []Cap{CapList})
	if s.Allow(p, CapCreate, "") {
		t.Error("create survived the downgrade")
	}
	if !s.Allow(p, CapAttach, "sess1") {
		t.Error("the existing session grant was lost")
	}
}

func TestLegacyAttachGrantStillWatchesAndReads(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	s := NewStore()
	p := s.Add("legacy", pub, nil)
	if err := s.Grant(pub, "sess1", CapAttach); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Cap{CapAttach, CapWatch, CapRead} {
		if !s.Allow(p, c, "sess1") {
			t.Errorf("legacy attach grant denied %s", c)
		}
	}
}
