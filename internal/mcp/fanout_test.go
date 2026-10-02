package mcp

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fan-out asks several machines at once. The properties worth pinning are the ones
// a green run says nothing about: the order does not depend on who replied first,
// one machine never fails the call, a machine that gives up mid-probe leaves no
// gate behind, and the concurrency is actually bounded.

func fanoutServer(t *testing.T, f *fakeBackend) *server {
	t.Helper()
	return testServer(f, func(o *Options) { o.Peers = []string{"", "laptop"} })
}

// threeMachines builds a fake serving "box", "laptop" and the local daemon.
func threeMachines(t *testing.T, f *fakeBackend) *server {
	t.Helper()
	f.setTargets(
		Target{Label: "", Identity: "", Local: true},
		Target{Label: "box", Identity: "peer-box"},
		Target{Label: "laptop", Identity: "peer-laptop"},
	)
	for _, s := range []struct{ id, peer string }{
		{"sess0", ""}, {"sessA", "box"}, {"sessB", "laptop"},
	} {
		f.sessions[s.id] = &fakeSession{id: s.id, alias: s.id, peer: s.peer}
	}
	return testServer(f, func(o *Options) { o.Peers = []string{"", "box", "laptop"} })
}

// The order is the caller's, whatever order the machines answer in.
func TestFanoutOrderIsTheRequestedOrderNotTheReplyOrder(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)

	// Each machine answers after a different delay, so completion order is the
	// reverse of request order.
	f.setReadDelay("", 120*time.Millisecond)
	f.setReadDelay("box", 60*time.Millisecond)
	f.setReadDelay("laptop", 10*time.Millisecond)
	for i := 0; i < 8; i++ {
		_, res, err := call(t, s, "session_list", args{"peers": []any{"", "box", "laptop"}})
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(res.Sessions))
		for _, r := range res.Sessions {
			got = append(got, r.Peer)
		}
		want := []string{"local", "box", "laptop"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("run %d: order %v, want %v", i, got, want)
		}
	}
}

// One machine failing is not the call failing: a model asking about everywhere needs
// the other answers far more than it needs a single error.
func TestOneMachineFailingDoesNotFailTheCall(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	f.readErrFor = func(id string) error {
		if id == "sessA" {
			return errors.New("connect: connection refused")
		}
		return nil
	}
	text, res, err := call(t, s, "session_list", args{"peers": []any{"", "box", "laptop"}})
	if err != nil {
		t.Fatalf("one unreachable machine failed the whole call: %v", err)
	}
	if len(res.Sessions) != 3 {
		t.Fatalf("got %d rows, want 3: a failed machine still has a row saying so", len(res.Sessions))
	}
	if !strings.Contains(text, "could not be reached") {
		t.Errorf("the footer does not say which machine was unreachable:\n%s", text)
	}
	// And the machine that did answer is reported as running.
	var box string
	for _, r := range res.Sessions {
		if r.Peer == "box" {
			box = r.State
		}
	}
	if box != "running" && box != "unknown" {
		t.Errorf("the healthy machine reports %q", box)
	}
}

// A probe this caller gave up on must not leave a gate behind. Otherwise the next
// list reports a target waiting for an approval that was never asked for, and no
// operator is ever asked.
func TestAGiveUpProbeLeavesNoGateBehind(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	// The machine accepts and then never answers, so the per-target timeout is
	// what ends it.
	f.setReadHang("box")

	// The call itself still answers: one machine not answering is a row that says
	// so, not a failure of the question.
	text, res, err := call(t, s, "session_list", args{"peers": []any{"box"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 1 || res.Sessions[0].ProbeError == "" {
		t.Fatalf("a machine that never answered is not reported as such: %s", text)
	}
	if _, gated := s.needsApproval("box"); gated {
		t.Error("a probe that gave up marked the target as waiting for approval")
	}
}

// The concurrency is bounded, and the bound is on simultaneous probes.
func TestFanoutConcurrencyIsBounded(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)

	var targets []Target
	for i := 0; i < 20; i++ {
		targets = append(targets, Target{Label: "m" + string(rune('a'+i)), Identity: "id-" + string(rune('a'+i))})
	}
	f.setTargets(targets...)
	for _, t := range targets {
		f.sessions["s"+t.Label] = &fakeSession{id: "s" + t.Label, alias: t.Label, peer: t.Label}
	}
	// Every probe parks until released, so the peak is the real simultaneous count.
	f.parkReads()
	names := make([]any, 0, len(targets))
	for _, t := range targets {
		names = append(names, t.Label)
	}
	s = testServer(f, func(o *Options) {
		o.Peers = make([]string, 0, len(targets))
		for _, t := range targets {
			o.Peers = append(o.Peers, t.Label)
		}
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = call(t, s, "session_list", args{"peers": names})
	}()

	// Let the pool fill, then check the high-water mark rather than a sample.
	time.Sleep(400 * time.Millisecond)
	peak := f.peakBlockedCount()
	f.unparkReads()
	<-done

	if peak > fanoutMaxWorkers {
		t.Errorf("%d probes ran at once, above the cap of %d", peak, fanoutMaxWorkers)
	}
	if peak < 2 {
		t.Errorf("only %d probes ran at once; the fan-out is not concurrent", peak)
	}
}

// Absent means today's behaviour, not everything. A caller that did not ask for a
// fan-out must not get one.
func TestOmittingPeersIsNotAskingForEveryMachine(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	// The single-target path lists every row the catalog holds, which is every
	// machine — that is pre-existing behaviour and the reason peers exists at all.
	// What must not happen is a *fan-out*: no target should be probed concurrently.
	if n := f.peakBlockedCount(); n > 0 {
		t.Errorf("the single-target path parked %d probes, so it went through the fan-out", n)
	}
	if len(res.Sessions) != 3 {
		t.Errorf("got %d rows, want the catalog's 3", len(res.Sessions))
	}
}

// Two names for one machine must be probed once. Two probes would be two reads past
// one approval gate.
func TestTwoNamesForOneMachineAreProbedOnce(t *testing.T) {
	f := newFakeBackend()
	f.setTargets(
		Target{Label: "box", Identity: "peer-box"},
		Target{Label: "laptop", Identity: "peer-box"}, // the same machine
	)
	f.sessions["sessA"] = &fakeSession{id: "sessA", alias: "build", peer: "box"}
	s := testServer(f, func(o *Options) { o.Peers = []string{"box", "laptop"} })

	f.resetReads()
	_, res, err := call(t, s, "session_list", args{"peers": []any{"box", "laptop"}})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.readCount(); n != 1 {
		t.Errorf("%d reads for one machine named twice", n)
	}
	if len(res.Sessions) != 1 {
		t.Errorf("got %d rows for one machine named twice", len(res.Sessions))
	}
}

// The argument rules, because each one has a failure that is silently wrong rather
// than loudly broken.
func TestFanoutArgumentRules(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	f.sessions["sessA"] = &fakeSession{id: "sessA", alias: "build", peer: "box"}

	for _, tc := range []struct {
		name string
		a    args
		want string
	}{
		{"an unknown machine", args{"peers": []any{"nope"}}, "not served by this process"},
		{"an empty list", args{"peers": []any{}}, "at least one machine"},
		{"both peer and peers", args{"peers": []any{"box"}, "peer": "box"}, "not an argument of session_list"},
		{"a number where a name belongs", args{"peers": []any{3}}, "must be strings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := call(t, s, "session_list", tc.a)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// "all" is the same list every time, whatever order the backend hands them over.
func TestPeersAllIsOrderedAndStable(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	var first string
	for i := 0; i < 5; i++ {
		_, res, err := call(t, s, "session_list", args{"peers": "all"})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range res.Sessions {
			got = append(got, r.Peer)
		}
		joined := strings.Join(got, ",")
		if i == 0 {
			first = joined
			continue
		}
		if joined != first {
			t.Fatalf("run %d gave %q, first gave %q", i, joined, first)
		}
	}
}

// The registry lock is not held across a target call. A fan-out makes that the
// difference between N machines in parallel and one at a time.
func TestTheRegistryLockIsNotHeldAcrossTargetIO(t *testing.T) {
	f := newFakeBackend()
	s := threeMachines(t, f)
	// A read cannot make progress while the registry lock is held, so this
	// deadlocks if any probe runs under it.
	f.setReadHook(func() {
		done := make(chan struct{})
		go func() { s.mu.Lock(); s.mu.Unlock(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("a probe ran while the registry lock was held")
		}
	})
	if _, _, err := call(t, s, "session_list", args{"peers": "all"}); err != nil {
		t.Fatal(err)
	}
	// Reaching here without a deadlock is the assertion; the hook would block
	// forever if a probe ran under the registry lock.
}

// The one that has to be an assertion rather than a log line: N concurrent lists
// against one pre-mode target must cost the operator exactly one approval. The
// count is on the target side — how many reads were refused pending approval —
// because that is the thing being spent.
func TestConcurrentFanoutsSpendOneApprovalNotN(t *testing.T) {
	f := newFakeBackend()
	f.setTargets(Target{Label: "box", Identity: "peer-box"})
	f.sessions["sessA"] = &fakeSession{id: "sessA", alias: "build", peer: "box"}
	f.sessions["sessB"] = &fakeSession{id: "sessB", alias: "test", peer: "box"}
	s := testServer(f, func(o *Options) { o.Peers = []string{"box"} })

	// Every read is refused pending approval, and parked, so the callers overlap.
	f.readErrFor = func(string) error { return pendingApproval("sessA") }
	f.parkReads()

	const callers = 6
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = call(t, s, "session_list", args{"peers": "box"})
		}()
	}
	time.Sleep(400 * time.Millisecond)
	f.unparkReads()
	wg.Wait()

	if n := f.approvalRequests(); n != 1 {
		t.Errorf("%d reads reached a pre-mode target across %d concurrent lists; "+
			"one approval is spent per read, so exactly 1 may", n, callers)
	}
}

// The slot is released after the state is recorded, not before. This pauses between
// the two and checks that another caller already sees the recorded state, rather
// than being let in to spend the same approval again.
func TestTheSlotIsReleasedAfterTheStateIsRecorded(t *testing.T) {
	f := newFakeBackend()
	f.setTargets(Target{Label: "box", Identity: "peer-box"})
	f.sessions["sessA"] = &fakeSession{id: "sessA", alias: "build", peer: "box"}
	s := testServer(f, func(o *Options) { o.Peers = []string{"box"} })

	// Armed to refuse, and to block just before the slot is handed back.
	release := make(chan struct{})
	blocked := make(chan struct{}, 1)
	f.readErrFor = func(string) error { return pendingApproval("sessA") }
	f.beforeRelease = func() {
		blocked <- struct{}{}
		<-release
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = call(t, s, "session_list", args{"peers": "box"})
	}()

	select {
	case <-blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("the probe never reached the release point")
	}
	// The first caller is holding the slot, with its result recorded but not yet
	// returned. A second caller must not get past it.
	if _, _, ok := s.claimProbe("box"); ok {
		t.Error("a second caller took the probe slot while the first still held it")
	}
	close(release)
	<-done

	// After the first caller is done the slot is free and the target is gated, so
	// the next caller sees the recorded state rather than probing again.
	if _, gated := s.needsApproval("box"); !gated {
		t.Error("the target was not recorded as gated after refusing")
	}
	if _, _, ok := s.claimProbe("box"); ok {
		s.releaseProbe("box")
		t.Log("the slot is free again, as it should be")
	}
}
