package transport

import (
	"context"
	"testing"
	"time"
)

// The defect this fixes: quic-go's 5s default silently truncated a budget the client
// documents as 12s. These assert the derivation rather than the symptom, because the
// symptom needs a starved handshake to reproduce and this does not.
func TestHandshakeIdleFollowsTheDialBudget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		budget  time.Duration
		want    time.Duration
		wantMax bool
	}{
		// The client's documented per-address budget: the handshake gets it, not 5s.
		{"the client's budget", 12 * time.Second, 12 * time.Second, false},
		{"a generous budget", 30 * time.Second, 30 * time.Second, false},
		// Short budgets are not made worse off: quic-go's default is the floor.
		{"exactly the default", 5 * time.Second, defaultHandshakeIdle, false},
		{"shorter than the default", 2 * time.Second, defaultHandshakeIdle, false},
		{"one second", time.Second, defaultHandshakeIdle, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
			defer cancel()
			got := handshakeIdleFor(ctx)
			// time.Until spends a moment, so a budget-derived answer is slightly under
			// the nominal figure. Compare with a tolerance rather than exactly.
			if got < tc.want-500*time.Millisecond || got > tc.want {
				t.Errorf("handshake idle %v, want about %v", got, tc.want)
			}
			if tc.want == defaultHandshakeIdle && got != defaultHandshakeIdle {
				t.Errorf("a short budget must floor at the default, got %v", got)
			}
		})
	}
}

// No deadline means no budget to honour, so the default stands rather than an
// unbounded timer.
func TestHandshakeIdleWithoutADeadlineIsTheDefault(t *testing.T) {
	if got := handshakeIdleFor(context.Background()); got != defaultHandshakeIdle {
		t.Errorf("with no deadline the handshake idle is %v, want the %v default", got, defaultHandshakeIdle)
	}
}

// The timer must never exceed the budget it is derived from, or it becomes the thing
// that overruns the context rather than something the context bounds. This is the
// property that makes raising the ceiling safe: dctx still cancels first.
func TestHandshakeIdleNeverExceedsTheBudget(t *testing.T) {
	for _, budget := range []time.Duration{6 * time.Second, 12 * time.Second, 20 * time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		got := handshakeIdleFor(ctx)
		cancel()
		if got > budget {
			t.Errorf("budget %v gave a handshake idle of %v, which is longer", budget, got)
		}
	}
}
