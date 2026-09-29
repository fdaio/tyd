package live

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingWriter is a PTY that never accepts input. The real one does not
// behave this way on Linux or macOS: both absorb a large write rather than
// blocking, which is why the bounds cannot be proven against a real PTY.
type blockingWriter struct {
	release chan struct{}
	mu      sync.Mutex
	written int
	once    sync.Once
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{release: make(chan struct{})}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	b.written += len(p)
	return len(p), nil
}

func (b *blockingWriter) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.written
}

func (b *blockingWriter) unblock() { b.once.Do(func() { close(b.release) }) }

// newTestAgent builds an agent wired to a fake writer. It mirrors the real
// construction closely enough for the send bounds, without a shell.
func newTestAgent(t *testing.T, write func([]byte) (int, error), sendTO time.Duration) *agent {
	t.Helper()
	a := &agent{
		dir:       t.TempDir(),
		meta:      Meta{SendTimeout: sendTO},
		cmdDone:   make(chan struct{}),
		writePTY:  write,
		closed:    false,
		outLog:    nil,
		waiters:   0,
		shellDone: make(chan struct{}),
		sendQueue: make(chan *sendJob, 8),
	}
	a.sendGen.Store(0)
	go a.sendWriter()
	return a
}

// A send that the PTY will not accept must give up on its own, report the
// bytes that did land, and write nothing more afterwards.
func TestSendTimesOutWithWrittenCount(t *testing.T) {
	w := newBlockingWriter()
	a := newTestAgent(t, w.Write, 150*time.Millisecond)

	type res struct {
		written int
		err     error
	}
	done := make(chan res, 1)
	go func() {
		n, err := a.awaitSend(make([]byte, 4096))
		done <- res{n, err}
	}()

	var r res
	select {
	case r = <-done:
		if !errors.Is(r.err, errSendTimeout) {
			t.Fatalf("want a send timeout, got %v", r.err)
		}
		// The chunk in flight is reported even though the write had not
		// returned, so a retry starts after it rather than repeating it.
		if r.written != sendChunk {
			t.Fatalf("written = %d, want the %d-byte chunk that was in flight", r.written, sendChunk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the send did not give up; the timeout is not enforced")
	}

	// Nothing may land beyond what was reported, or a retry would duplicate.
	w.unblock()
	time.Sleep(100 * time.Millisecond)
	if got, want := w.total(), r.written; got != want {
		t.Fatalf("wrote %d bytes but reported %d; a retry would duplicate", got, want)
	}
}

// An attach must be able to take the slot while a send is stuck, and the
// send must stop rather than keep typing.
func TestAttachPreemptsStuckSend(t *testing.T) {
	w := newBlockingWriter()
	a := newTestAgent(t, w.Write, time.Minute) // long enough that only preempt can stop it

	type res struct {
		written int
		err     error
	}
	done := make(chan res, 1)
	go func() {
		n, err := a.awaitSend(make([]byte, 4096))
		done <- res{n, err}
	}()

	// Let it get into the write, then take the slot the way an attach does.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	a.preemptSend()
	w.unblock() // stand in for the shell finally draining

	select {
	case r := <-done:
		if !errors.Is(r.err, errPreempted) {
			t.Fatalf("want preempted, got %v", r.err)
		}
		// The chunk already in flight may complete; that is what written is for.
		if r.written != sendChunk {
			t.Fatalf("written = %d, want the %d-byte chunk that was in flight", r.written, sendChunk)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the send was not preempted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("preempt took %s, an attach must not wait on a send", elapsed)
	}
}

// A partial write is reported honestly, so a retry resumes from the right
// offset rather than repeating what already landed.
func TestSendReportsPartialWriteOnPreempt(t *testing.T) {
	release := make(chan struct{})
	var wg sync.WaitGroup
	// Write the first chunk, then block on the rest.
	var mu sync.Mutex
	written := 0
	write := func(p []byte) (int, error) {
		mu.Lock()
		written += len(p)
		n := written
		mu.Unlock()
		if n > 1024 {
			<-release
		}
		return len(p), nil
	}
	a := newTestAgent(t, write, time.Minute)

	type res struct {
		written int
		err     error
	}
	done := make(chan res, 1)
	go func() {
		c, err := a.awaitSend(make([]byte, 4096))
		done <- res{c, err}
	}()
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	a.preemptSend()
	close(release)

	select {
	case r := <-done:
		if !errors.Is(r.err, errPreempted) {
			t.Fatalf("want preempted, got %v", r.err)
		}
		if r.written != 2048 {
			t.Fatalf("written = %d, want the two chunks taken before the preempt", r.written)
		}
		if r.written%sendChunk != 0 && r.written != 0 {
			t.Fatalf("written %d is not a chunk boundary, the count is not resumable", r.written)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the send was not preempted")
	}
}

// Two sends must not interleave; the second is told to retry rather than
// queueing behind the first.
func TestSecondSendIsBusyNotQueued(t *testing.T) {
	w := newBlockingWriter()
	a := newTestAgent(t, w.Write, time.Minute)

	first := make(chan struct{})
	go func() {
		defer close(first)
		_, _ = a.awaitSend(make([]byte, 4096))
	}()
	time.Sleep(50 * time.Millisecond)

	// A second send is refused rather than queued behind the first.
	_, second := a.awaitSend(make([]byte, 16))
	if !errors.Is(second, errSendBusy) {
		t.Fatalf("a concurrent send should be refused as busy, got %v", second)
	}
	if !errors.Is(errSendBusy, errSendBusy) || errSendBusy.Error() != "session busy: a send is in progress" {
		t.Fatalf("busy error should be actionable, got %q", errSendBusy)
	}

	w.unblock()
	<-first

	// After it finishes, the slot is free again.
	if _, err := a.awaitSend(nil); errors.Is(err, errSendBusy) {
		t.Fatal("the slot should be released when the send ends")
	}
}

// The configured timeout is clamped to the cap, so a caller cannot ask for
// a send that never returns.
func TestSendTimeoutIsClamped(t *testing.T) {
	a := newTestAgent(t, func(p []byte) (int, error) { return len(p), nil }, 0)
	if got := a.sendTimeout(); got != DefaultSendTimeout {
		t.Fatalf("zero should mean the default, got %s", got)
	}
	a = newTestAgent(t, func(p []byte) (int, error) { return len(p), nil }, 10*time.Minute)
	if got := a.sendTimeout(); got != MaxSendTimeout {
		t.Fatalf("a huge timeout should clamp to %s, got %s", MaxSendTimeout, got)
	}
	a = newTestAgent(t, func(p []byte) (int, error) { return len(p), nil }, 2*time.Second)
	if got := a.sendTimeout(); got != 2*time.Second {
		t.Fatalf("a sane timeout should pass through, got %s", got)
	}
}
