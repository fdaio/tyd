package live

import (
	"bytes"
	"testing"
	"time"
)

// condLog is a log with the background writer out of the way, so a test
// controls exactly what lands and when.
func condLog(t *testing.T) *outputLog {
	t.Helper()
	l := openOutputLog(t.TempDir(), 64<<20)
	t.Cleanup(l.Close)
	return l
}

func mustCond(t *testing.T, idleMS uint32, pattern string, maxBytes uint32) Conditions {
	t.Helper()
	c, err := ValidateConditions(idleMS, pattern, maxBytes)
	if err != nil {
		t.Fatalf("conditions: %v", err)
	}
	return c
}

func TestValidateConditions(t *testing.T) {
	if c := mustCond(t, 0, "", 0); c.Any() {
		t.Fatal("no conditions should not count as any")
	}
	c := mustCond(t, 500, "assword", 4096)
	if !c.Any() || c.Idle != 500*time.Millisecond || c.Match.String() != "assword" || c.MaxBytes != 4096 {
		t.Fatalf("%+v", c)
	}
}

func TestValidateConditionsRejects(t *testing.T) {
	cases := []struct {
		name      string
		idle, max uint32
		pattern   string
	}{
		{"idle below floor", 10, 0, ""},
		{"idle above ceiling", 30001, 0, ""},
		{"max above ceiling", 0, (64 << 10) + 1, ""},
		{"pattern too long", 0, 0, string(bytes.Repeat([]byte("a"), MaxMatchPattern+1))},
		{"bad pattern", 0, 0, "([unclosed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateConditions(tc.idle, tc.pattern, tc.max); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	// The boundaries themselves are allowed.
	if _, err := ValidateConditions(MinIdleMS, "", 0); err != nil {
		t.Fatalf("idle floor: %v", err)
	}
	if _, err := ValidateConditions(MaxIdleMS, "", 0); err != nil {
		t.Fatalf("idle ceiling: %v", err)
	}
	if _, err := ValidateConditions(0, string(bytes.Repeat([]byte("a"), MaxMatchPattern)), 0); err != nil {
		t.Fatalf("pattern ceiling: %v", err)
	}
}

// A pattern at the ceiling compiles; RE2 keeps it linear, so a long one is a
// legibility problem, not a denial of service.
func TestValidateLongPatternCompiles(t *testing.T) {
	pat := "^" + string(bytes.Repeat([]byte("a"), MaxMatchPattern-2)) + "$"
	if _, err := ValidateConditions(0, pat, 0); err != nil {
		t.Fatalf("want a valid pattern at the cap, got %v", err)
	}
}

// A read with no conditions still returns at once when there is data.
func TestReadNoConditionsReturnsImmediately(t *testing.T) {
	l := condLog(t)
	l.Append([]byte("hello"))
	res := l.ReadAtWait(0, 0, 5*time.Second, Conditions{}, func() bool { return false })
	if res.Reason != ReasonAvailable {
		t.Fatalf("reason = %q", res.Reason)
	}
	if !bytes.Contains(res.Data, []byte("hello")) {
		t.Fatalf("data = %q", res.Data)
	}
}

// match fires on a prompt, even when the prompt is coloured and split across
// two writes. The pattern is a literal "$ " because RE2's $ is an end anchor,
// and a prompt is followed by a space rather than ending the text.
func TestReadUntilMatchPrompt(t *testing.T) {
	l := condLog(t)
	cond := mustCond(t, 0, `\$ `, 0)
	go func() {
		time.Sleep(80 * time.Millisecond)
		// The escape is deliberately split across two writes.
		l.Append([]byte("pass\x1b[01;3"))
		time.Sleep(40 * time.Millisecond)
		l.Append([]byte("2mword\x1b[0m$ "))
	}()
	res := l.ReadAtWait(0, 0, 5*time.Second, cond, func() bool { return false })
	if res.Reason != ReasonMatch {
		t.Fatalf("reason = %q data = %q", res.Reason, res.Data)
	}
}

// Data already at the cursor does not satisfy a condition on its own.
func TestReadConditionIgnoresExistingData(t *testing.T) {
	l := condLog(t)
	l.Append([]byte("no match here"))
	start := time.Now()
	res := l.ReadAtWait(0, 0, 300*time.Millisecond, mustCond(t, 0, "never-matches", 0), func() bool { return false })
	if res.Reason != ReasonTimeout {
		t.Fatalf("reason = %q, want timeout", res.Reason)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("returned too early: %s", elapsed)
	}
}

// idle only counts once something has actually been produced.
func TestReadUntilIdle(t *testing.T) {
	l := condLog(t)
	cond := mustCond(t, 100, "", 0)

	// Nothing yet: the clock never starts, so this can only time out.
	start := time.Now()
	res := l.ReadAtWait(0, 0, 400*time.Millisecond, cond, func() bool { return false })
	if res.Reason != ReasonTimeout {
		t.Fatalf("silent session: reason = %q", res.Reason)
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("idle fired with no output: %s", elapsed)
	}

	// With output, it fires once the stream goes quiet.
	go func() {
		time.Sleep(50 * time.Millisecond)
		l.Append([]byte("some output\n"))
	}()
	start = time.Now()
	res = l.ReadAtWait(0, 0, 3*time.Second, cond, func() bool { return false })
	if res.Reason != ReasonIdle {
		t.Fatalf("reason = %q", res.Reason)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("idle took %s", elapsed)
	}
}

// Output that keeps arriving must keep resetting the idle clock. If idle were
// measured from the start of the read instead of the last byte, a session
// producing output every 50ms would still report idle after 150ms.
func TestReadUntilIdleNotFiredBySteadyOutput(t *testing.T) {
	l := condLog(t)
	const idleMS = 200
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(40 * time.Millisecond):
				l.Append([]byte("tick\n"))
			}
		}
	}()
	start := time.Now()
	res := l.ReadAtWait(0, 0, 600*time.Millisecond, mustCond(t, idleMS, "", 0), func() bool { return false })
	elapsed := time.Since(start)
	close(stop)
	<-done

	if res.Reason != ReasonTimeout {
		t.Fatalf("steady output must not look idle, got %q after %s", res.Reason, elapsed)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("returned after only %s", elapsed)
	}
}

// max_bytes cuts the page to exactly the request, on a rune boundary.
func TestReadUntilMaxBytes(t *testing.T) {
	l := condLog(t)
	// Four 3-byte runes plus ASCII.
	l.Append([]byte("你好世界tail"))
	res := l.ReadAtWait(0, 0, time.Second, mustCond(t, 0, "", 5), func() bool { return false })
	if res.Reason != ReasonMaxBytes {
		t.Fatalf("reason = %q", res.Reason)
	}
	// 5 lands inside the second rune, so it must back off to 3.
	if len(res.Data) != 3 {
		t.Fatalf("len = %d, want 3 (rune boundary)", len(res.Data))
	}
	if res.CursorNext != 3 {
		t.Fatalf("cursor_next = %d, want 3", res.CursorNext)
	}
	// Reading on from there loses and duplicates nothing.
	rest := l.ReadAt(res.CursorNext, res.Epoch)
	all := append(append([]byte(nil), res.Data...), rest.Data...)
	if !bytes.Equal(all, []byte("你好世界tail")) {
		t.Fatalf("paged = %q", all)
	}
}

func TestReadUntilMaxBytesExact(t *testing.T) {
	l := condLog(t)
	l.Append(bytes.Repeat([]byte("y"), 100))
	res := l.ReadAtWait(0, 0, time.Second, mustCond(t, 0, "", 40), func() bool { return false })
	if res.Reason != ReasonMaxBytes {
		t.Fatalf("reason = %q", res.Reason)
	}
	if len(res.Data) != 40 {
		t.Fatalf("len = %d, want 40", len(res.Data))
	}
	if res.CursorNext != 40 {
		t.Fatalf("cursor_next = %d", res.CursorNext)
	}
}

// An exited shell returns at once with its own reason.
func TestReadConditionExited(t *testing.T) {
	l := condLog(t)
	exited := false
	_ = exited
	start := time.Now()
	res := l.ReadAtWait(0, 0, 10*time.Second, mustCond(t, 0, "never", 0), func() bool { return true })
	if res.Reason != ReasonExited {
		t.Fatalf("reason = %q", res.Reason)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("exited waited %s", elapsed)
	}
}

// cursor_ahead and dropped still come back at once, without waiting.
func TestReadConditionsImmediateRepairs(t *testing.T) {
	l := condLog(t)
	start := time.Now()
	res := l.ReadAtWait(1<<40, 0, 5*time.Second, mustCond(t, 0, "never", 0), func() bool { return false })
	if res.Reason != ReasonCursorHead {
		t.Fatalf("reason = %q", res.Reason)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cursor_ahead waited")
	}
}

// reason and the exited flag must agree, or a caller cannot trust either.
func TestReasonMatchesExitedFlag(t *testing.T) {
	l := condLog(t)
	res := l.ReadAtWait(0, 0, 200*time.Millisecond, mustCond(t, 0, "never", 0), func() bool { return true })
	if res.Reason == ReasonExited && !res.Exited {
		t.Fatal("reason said exited but the flag did not")
	}
	if res.Exited && res.Reason != ReasonExited {
		t.Fatalf("flag set but reason = %q", res.Reason)
	}
}

// A busy session must not spend the CPU re-running the pattern on every wake.
func TestMatchEvaluationIsRateLimited(t *testing.T) {
	l := condLog(t)
	cond := mustCond(t, 0, "zzzzz-never", 0)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := bytes.Repeat([]byte("y"), 256)
		for {
			select {
			case <-stop:
				return
			default:
				l.Append(buf)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	<-done
	l.mu.Lock()
	before := l.matchEvals
	l.mu.Unlock()
	res := l.ReadAtWait(0, 0, 400*time.Millisecond, cond, func() bool { return false })
	if res.Reason != ReasonTimeout {
		t.Fatalf("reason = %q", res.Reason)
	}
	// Without a limit this would be thousands of runs against 16KB.
	l.mu.Lock()
	evals := l.matchEvals - before
	l.mu.Unlock()
	if evals > 100 {
		t.Fatalf("match evaluated %d times in 400ms", evals)
	}
	t.Logf("match evaluations in 400ms: %d", evals)
}

// The pattern is matched against cleaned text, so colour does not hide it.
func TestMatchIgnoresAnsi(t *testing.T) {
	l := condLog(t)
	l.Append([]byte("\x1b[01;31mERROR\x1b[0m: failed"))
	res := l.ReadAtWait(0, 0, 500*time.Millisecond, mustCond(t, 0, "ERROR: failed", 0), func() bool { return false })
	if res.Reason != ReasonMatch {
		t.Fatalf("reason = %q data = %q", res.Reason, res.Data)
	}
}
