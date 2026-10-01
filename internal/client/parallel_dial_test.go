package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tyd/internal/transport"
)

// Racing candidates is only safe if three things hold, and none of them are visible
// from the outside: exactly one login, no connection left open by an attempt that
// lost, and a stagger rather than a simultaneous burst. So the two steps are behind
// a seam and the tests count logins and watch connections close.

// dialRecord is one candidate's attempt, as the fake saw it.
type dialRecord struct {
	mu      sync.Mutex
	started []string
	logins  int
	closed  []string
	opened  []string
}

func (r *dialRecord) start(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, addr)
}

func (r *dialRecord) counts() (logins, opened, closed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logins, len(r.opened), len(r.closed)
}

func (r *dialRecord) starts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.started...)
}

// fakeVerify returns a verify step that answers for the named addresses after the
// given delays, and refuses the rest.
func fakeVerify(rec *dialRecord, ok map[string]time.Duration) func(context.Context, Endpoint) (*Conn, []byte, error) {
	return func(ctx context.Context, ep Endpoint) (*Conn, []byte, error) {
		rec.start(ep.Address)
		wait, works := ok[ep.Address]
		if !works {
			return nil, nil, errors.New("connection refused")
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		rec.mu.Lock()
		rec.opened = append(rec.opened, ep.Address)
		rec.mu.Unlock()
		return &Conn{nc: &fakeConn{addr: ep.Address, rec: rec}, info: transport.Info{RemoteAddr: ep.Address}}, nil, nil
	}
}

func fakeLogin(rec *dialRecord) func(context.Context, *Conn, []byte, Endpoint, ed25519.PrivateKey) error {
	return func(context.Context, *Conn, []byte, Endpoint, ed25519.PrivateKey) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.logins++
		return nil
	}
}

func withSeams(t *testing.T, rec *dialRecord, ok map[string]time.Duration) {
	t.Helper()
	oldVerify, oldLogin := verifyForTest, loginForTest
	verifyForTest, loginForTest = fakeVerify(rec, ok), fakeLogin(rec)
	t.Cleanup(func() { verifyForTest, loginForTest = oldVerify, oldLogin })
}

func testEndpoint() Endpoint {
	return Endpoint{Kind: "tls", Address: "a", CertFP: "ff"}
}

// A dead first candidate must not cost a whole connect timeout, and the address
// that answers must be the one used.
func TestTheStaggeredRaceSkipsADeadCandidateFast(t *testing.T) {
	rec := &dialRecord{}
	// "dead" is absent on purpose: it refuses, which is the case being measured.
	// Listing it with a zero delay would make it the fastest answer.
	withSeams(t, rec, map[string]time.Duration{
		"slow": 900 * time.Millisecond,
		"live": 260 * time.Millisecond, // answers just after the second stagger
	})

	start := time.Now()
	c, _, err := dialCandidates(t.Context(), testEndpoint(), nil,
		[]string{"dead", "slow", "live"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("no connection")
	}
	if elapsed >= 800*time.Millisecond {
		t.Errorf("took %s; a dead and a slow candidate should not have been waited out", elapsed)
	}
	if got := c.nc.(*fakeConn).addr; got != "live" {
		t.Errorf("connected to %q, want the candidate that answered", got)
	}
}

// The one that matters most: a login is visible to the target, which can ask for
// an approval or rate limit. N logins for one dial is a defect, not a style choice.
func TestOneLoginPerDialNoMatterHowManyCandidatesAnswer(t *testing.T) {
	rec := &dialRecord{}
	// Three addresses answer, all within one stagger of each other.
	withSeams(t, rec, map[string]time.Duration{
		"a": 10 * time.Millisecond,
		"b": 20 * time.Millisecond,
		"c": 30 * time.Millisecond,
	})
	c, _, err := dialCandidates(t.Context(), testEndpoint(), nil, []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	if logins, _, _ := rec.counts(); logins != 1 {
		t.Errorf("%d logins for one dial; a login is visible to the target, so exactly one may happen", logins)
	}
	if c.nc.(*fakeConn).addr != "a" {
		t.Errorf("the winner was %q, so the assertions about losers would be about the wrong ones", c.nc.(*fakeConn).addr)
	}
	// Every connection that opened has to end. The winner's is the caller's to
	// close, so it is the one exception.
	for _, loser := range rec.openedExcept("a") {
		if !rec.wasClosed(loser) {
			t.Errorf("candidate %q opened and was never closed", loser)
		}
	}
}

// A candidate that is still working when the race is decided must not be left
// holding a connection. Cancelling usually stops it before it opens one at all; the
// case worth pinning is the one where it wins that race by a hair, so its window is
// short enough to land between the decision and the cancel taking effect.
func TestACandidateStillInFlightIsClosedRatherThanLeftOpen(t *testing.T) {
	rec := &dialRecord{}
	withSeams(t, rec, map[string]time.Duration{
		"first": 10 * time.Millisecond,
		"near":  250 * time.Millisecond, // opens around the moment the race is decided
	})
	c, _, err := dialCandidates(t.Context(), testEndpoint(), nil, []string{"first", "near"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	_ = c.Close()

	for _, addr := range rec.openedExcept(rec.winnerIfClosed()) {
		if !rec.wasClosed(addr) {
			t.Errorf("candidate %q opened and was never closed", addr)
		}
	}
	if rec.anyOpenUnclosedExceptOne() {
		t.Errorf("a candidate is still holding a connection: opened %v, closed %v",
			rec.starts(), rec.closes())
	}
}

func TestEveryCandidateFailingNamesThemAll(t *testing.T) {
	rec := &dialRecord{}
	withSeams(t, rec, map[string]time.Duration{})
	_, errs, err := dialCandidates(t.Context(), testEndpoint(), nil, []string{"a", "b", "c"})
	if err == nil {
		t.Fatal("expected a failure")
	}
	if len(errs) != 3 {
		t.Errorf("got %d errors for 3 candidates: %v", len(errs), errs)
	}
	if !strings.Contains(err.Error(), "every candidate address failed") {
		t.Errorf("unhelpful summary: %v", err)
	}
}

// A single candidate has nothing to race, and coordinating one anyway is only more
// ways to be wrong.
func TestOneCandidateKeepsTheSerialPath(t *testing.T) {
	rec := &dialRecord{}
	withSeams(t, rec, map[string]time.Duration{"only": 0})
	c, _, err := dialCandidates(t.Context(), testEndpoint(), nil, []string{"only"})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if starts := rec.starts(); len(starts) != 1 || starts[0] != "only" {
		t.Errorf("started %v, want just the one candidate", starts)
	}
	if logins, _, _ := rec.counts(); logins != 1 {
		t.Errorf("%d logins for one candidate", logins)
	}
}

// fakeConn is a connection that only knows what it is and when it closed.
type fakeConn struct {
	addr string
	rec  *dialRecord
}

func (c *fakeConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakeConn) Close() error {
	c.rec.mu.Lock()
	defer c.rec.mu.Unlock()
	c.rec.closed = append(c.rec.closed, c.addr)
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) Info() transport.Info             { return transport.Info{RemoteAddr: c.addr} }

// openedExcept lists the addresses that opened a connection, minus one.
func (r *dialRecord) openedExcept(addr string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, a := range r.opened {
		if a != addr {
			out = append(out, a)
		}
	}
	return out
}

func (r *dialRecord) wasClosed(addr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.closed {
		if a == addr {
			return true
		}
	}
	return false
}

func (r *dialRecord) closes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.closed...)
}

// winnerIfClosed is the address the race settled on, worked out from what closed.
func (r *dialRecord) winnerIfClosed() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.opened {
		seen := false
		for _, c := range r.closed {
			if c == a {
				seen = true
			}
		}
		if !seen {
			return a
		}
	}
	return ""
}

func (r *dialRecord) anyOpenUnclosedExceptOne() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	unclosed := 0
	for _, a := range r.opened {
		seen := false
		for _, c := range r.closed {
			if c == a {
				seen = true
			}
		}
		if !seen {
			unclosed++
		}
	}
	return unclosed > 1
}
