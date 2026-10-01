package mcp

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// At most one probe per target may be in flight. needsApproval and markGated are
// two separate locked calls with the probe between them, so without a slot N
// probes all pass the check before any of them sets the mark — and on a pre-mode
// target that is one operator approval spent N times.
//
// This is invisible while probing is serial, which is why nothing caught it before
// anyone proposed running probes concurrently. The count of reads that actually
// reached the target is the measure: one read is one approval spent.

func TestConcurrentListsSpendOneApprovalNotEight(t *testing.T) {
	f := newFakeBackend()
	f.sessions["sess1"] = &fakeSession{id: "sess1", alias: "build"}
	f.sessions["sess2"] = &fakeSession{id: "sess2", alias: "test"}
	s := testServer(f, nil)

	// The target refuses every read pending approval, which is the situation that
	// makes an extra probe cost something: each read that gets through spends the
	// operator's one approval. A probe that merely succeeds would let every caller
	// probe again in turn, correctly, and the test would measure nothing.
	f.readErrFor = func(string) error { return pendingApproval("sess1") }

	// Park every read so the callers really overlap. Without that they would run
	// one after another and the test would pass whether or not the slot exists.
	f.parkReads()

	const callers = 8
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := call(t, s, "session_list", args{}); err != nil {
				t.Error(err)
			}
		}()
	}

	// Wait until a read has arrived, then give the others long enough to have
	// reached their probe too. Without the extra time a slow caller could look
	// correct by never having got there.
	deadline := time.Now().Add(5 * time.Second)
	for f.readCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(250 * time.Millisecond)
	f.unparkReads()
	wg.Wait()

	if n := f.readCount(); n != 1 {
		t.Errorf("%d reads reached one target, so one operator approval would be spent %d times; "+
			"at most 1 read may be in flight per target", n, n)
	}
}

func TestTheSlotIsReleasedAfterAProbe(t *testing.T) {
	// A slot that is never released would make every later row on that target read
	// as "another list is probing", which is a worse answer than a probe.
	s := testServer(newFakeBackend(), nil)
	const peer = "box"

	if !s.claimProbe(peer) {
		t.Fatal("the first claim was refused")
	}
	if s.claimProbe(peer) {
		t.Error("a second claim was allowed while one was held")
	}
	s.releaseProbe(peer)
	if !s.claimProbe(peer) {
		t.Error("the claim was not released")
	}
	s.releaseProbe(peer)
}

func TestASkippedRowSaysItWasSkippedNotThatApprovalIsPending(t *testing.T) {
	// Two different situations, and a reader has to tell them apart: one waits for
	// an operator, the other waits for another caller. Conflating them would send a
	// model to wait for an approval that is not the thing holding it up.
	f := newFakeBackend()
	f.sessions["sess1"] = &fakeSession{id: "sess1", alias: "build"}
	s := testServer(f, nil)

	if !s.claimProbe("") {
		t.Fatal("could not take the slot")
	}
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	s.releaseProbe("")

	if len(res.Sessions) != 1 {
		t.Fatalf("got %d rows", len(res.Sessions))
	}
	got := res.Sessions[0].ProbeError
	if !strings.Contains(got, "already probing") {
		t.Errorf("a skipped row does not say it was skipped: %q", got)
	}
	if strings.Contains(got, "requires approval") {
		t.Errorf("a skipped row claims the target requires approval: %q", got)
	}
}

func TestAGatedRowSaysHowLongApprovalHasBeenPending(t *testing.T) {
	// "Waiting for approval" and "waiting since this morning" call for different
	// responses, and one line saying only that it is waiting cannot tell them
	// apart.
	f := newFakeBackend()
	f.sessions["sess1"] = &fakeSession{id: "sess1", alias: "build"}
	s := testServer(f, nil)
	s.markGated("")

	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 1 {
		t.Fatalf("got %d rows", len(res.Sessions))
	}
	if got := res.Sessions[0].ProbeError; !strings.Contains(got, "Approval pending since ") {
		t.Errorf("a gated row does not say since when: %q", got)
	}
}

func TestMarkingTwiceDoesNotMoveThePendingTime(t *testing.T) {
	// The target asked once. A later probe attempt that also failed did not make
	// it ask again, so the time a model is told must be the first one.
	s := testServer(newFakeBackend(), nil)

	s.markGated("box")
	first, gated := s.needsApproval("box")
	if !gated {
		t.Fatal("not gated")
	}
	time.Sleep(2 * time.Millisecond)
	s.markGated("box")
	second, _ := s.needsApproval("box")
	if !first.Equal(second) {
		t.Errorf("re-marking moved the pending time: %v then %v", first, second)
	}
}

func TestTheMarkIsNotPersistedAcrossServers(t *testing.T) {
	// The mark is process memory on purpose: a restart that resurrected it would
	// report a block the operator has already lifted, sending a model to wait for a
	// gate that has closed. This pins that a new server starts clean.
	backend := newFakeBackend()
	s := testServer(backend, nil)
	s.markGated("box")

	// A second server over the same backend, so over the same disk state.
	fresh := testServer(backend, nil)
	if _, gated := fresh.needsApproval("box"); gated {
		t.Error("the mark came back in a new server, so something is persisting it")
	}
}
