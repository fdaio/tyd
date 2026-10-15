package session

import (
	"strings"
	"testing"
	"time"

	"tyd/internal/live"
)

// Dimension 3: wait determinism.
//
// An agent must be able to say "wake me when X" instead of polling and
// guessing. The wake must be precise: not before the condition holds,
// not long after.

func TestDetWaitMatchWakesOnTime(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	// A command that prints its marker after a delay. The read must
	// return promptly after the marker appears — not at the full wait
	// timeout (which would mean the condition was ignored and the
	// driver fell back to waiting blindly).
	reply, err := s.Send([]byte("sleep 1; echo punctual-marker\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := s.Read(reply.Cursor, reply.Epoch, 10*time.Second, live.ReadConditions{
		Match: "punctual-marker",
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if !strings.Contains(string(res.Data), "punctual-marker") {
		t.Fatalf("match token missing from wake data: %q", res.Data)
	}
	// Generous upper bound: must wake well before the 10s timeout.
	// (1s sleep + scheduling slack; 8s would indicate polling fallback.)
	if elapsed > 8*time.Second {
		t.Fatalf("wake took %v, condition was not honoured promptly", elapsed)
	}
}

func TestDetWaitMaxBytesCapsData(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	// Produce more output than the cap, then read with MaxBytes.
	// The read must come back BECAUSE the cap was hit
	// (Reason == "max-bytes") with at most MaxBytes of data —
	// a declared bound, not a guess about "enough output".
	reply, err := s.Send([]byte("seq 1 10000\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	const cap = 100
	res, err := s.Read(reply.Cursor, reply.Epoch, 5*time.Second, live.ReadConditions{
		MaxBytes: cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != live.ReasonMaxBytes {
		t.Fatalf("expected read reason %q, got %q", live.ReasonMaxBytes, res.Reason)
	}
	if len(res.Data) > cap {
		t.Fatalf("MaxBytes violated: got %d bytes, cap %d", len(res.Data), cap)
	}
}

func TestDetWaitIdleDetectsQuiet(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	reply, err := s.Send([]byte("echo idle-probe; sleep 2\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	// IdleMS declares "wake me when output has been quiet this long".
	// MinIdleMS bounds apply; use a value safely above the minimum.
	res, err := s.Read(reply.Cursor, reply.Epoch, 10*time.Second, live.ReadConditions{
		IdleMS: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != live.ReasonIdle {
		t.Fatalf("expected read reason %q, got %q", live.ReasonIdle, res.Reason)
	}
}
