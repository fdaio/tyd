package relay

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSecondOfferIsRefusedAndFirstSurvives(t *testing.T) {
	h := NewHub()

	first, firstClient := net.Pipe()
	firstDone := make(chan struct{})
	go func() {
		h.handleOffer(first, Msg{Type: TypeOffer, DaemonID: "daemon-1"})
		close(firstDone)
	}()
	if msg, err := ReadMsg(firstClient); err != nil || msg.Type != TypeOK {
		t.Fatalf("first offer: %+v %v", msg, err)
	}

	second, secondClient := net.Pipe()
	secondDone := make(chan struct{})
	go func() {
		h.handleOffer(second, Msg{Type: TypeOffer, DaemonID: "daemon-1"})
		close(secondDone)
	}()
	msg, err := ReadMsg(secondClient)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != TypeError || !strings.Contains(msg.Error, "active offer") {
		t.Fatalf("second offer = %+v, want an active-offer refusal", msg)
	}
	_ = secondClient.Close()
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("the refused offer handler did not return")
	}

	// The first offer is still the one a dial would reach.
	h.mu.Lock()
	cur := h.offers["daemon-1"]
	h.mu.Unlock()
	if cur == nil || cur.control != first {
		t.Fatal("the refused offer displaced the live one")
	}

	_ = firstClient.Close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("the first offer did not stop after its connection closed")
	}

	third, thirdClient := net.Pipe()
	thirdDone := make(chan struct{})
	go func() {
		h.handleOffer(third, Msg{Type: TypeOffer, DaemonID: "daemon-1"})
		close(thirdDone)
	}()
	if msg, err := ReadMsg(thirdClient); err != nil || msg.Type != TypeOK {
		t.Fatalf("offer after the first closed: %+v %v", msg, err)
	}
	_ = thirdClient.Close()
	<-thirdDone
}
