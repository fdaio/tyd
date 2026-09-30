package mcp

import (
	"context"
	"io"
	"os"
	"runtime"
	"testing"
	"time"
)

// settle waits for goroutines that are already on their way out, so the count is
// of leaks rather than of teardown in progress.
func settle() int {
	for i := 0; i < 40; i++ {
		runtime.Gosched()
		time.Sleep(25 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// Serve must leave nothing behind on any of the three ways a client goes away:
// the input closing, the context being cancelled, and a call still in flight.
func TestServeLeavesNoGoroutines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		leave func(in *os.File, cancel context.CancelFunc)
	}{
		{"input closed", func(in *os.File, _ context.CancelFunc) { _ = in.Close() }},
		{"context cancelled", func(_ *os.File, cancel context.CancelFunc) { cancel() }},
		{"both", func(in *os.File, cancel context.CancelFunc) { cancel(); _ = in.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := settle()
			for i := 0; i < 5; i++ {
				f := newFakeBackend()
				srv := testServer(f, nil)
				// Opened before the gate goes in: the open does a read of its own,
				// which would otherwise park on the gate and the open would never
				// return.
				if _, _, err := call(t, srv, "session_open", args{"name": "build"}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := call(t, testServer(f, nil), "session_open", args{"name": "build"}); err != nil {
					t.Fatal(err)
				}
				inR, inW, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				outR, outW, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- Serve(ctx, inR, outW, f, io.Discard, Options{MaxSessions: 2}) }()
				go func() { _, _ = outR.Read(make([]byte, 1)) }()

				// A call still parked when the client goes away. This is the shape
				// most likely to leave something behind: Serve has a call, a read
				// and a writer to stop, and the read is blocked on the target.
				f.readGate = make(chan struct{})
				parked := make(chan struct{})
				go func() {
					defer close(parked)
					_, _, _ = srv.dispatch(context.Background(), "session_read",
						args{"session": "build", "wait": 5000})
				}()
				time.Sleep(150 * time.Millisecond)
				tc.leave(inW, cancel)
				// The parked call is released with the client; if it is not, the
				// wait below is what says so rather than the goroutine count.
				select {
				case <-parked:
				case <-time.After(10 * time.Second):
					close(f.readGate)
					t.Fatal("a parked call outlived the client")
				}
				close(f.readGate)
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("Serve did not return")
				}
				cancel()
				_ = inR.Close()
				_ = outR.Close()
				_ = outW.Close()
			}
			after := settle()
			t.Logf("goroutines %d -> %d", before, after)
			if after > before+2 {
				buf := make([]byte, 1<<16)
				buf = buf[:runtime.Stack(buf, true)]
				t.Fatalf("goroutines %d -> %d after Serve returned:\n%s", before, after, buf)
			}
		})
	}
}
