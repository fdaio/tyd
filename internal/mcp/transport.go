package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// serverVersion is reported in initialize. It is the module version of this
// build, not a protocol number.
const serverVersion = "0.1.0"

// shutdownGrace is how long the exit sequence waits for a cancelled call to
// finish. It is longer than a cancelled call should ever need, because the point
// is to let a read release its slot, and short enough that a call wedged
// somewhere it cannot be cancelled does not keep the process alive. It is a
// variable so a test does not have to spend five seconds proving it gives up.
var shutdownGrace = 5 * time.Second

// conn is one stdio conversation: the frames it writes, the in-flight calls it
// can cancel, and the tool set behind them.
type conn struct {
	srv *server
	log *logger
	enc *encoder

	mu sync.Mutex
	// calls holds every in-flight call, keyed by the raw request id, so a
	// cancellation reaches the right one.
	calls map[string]*callState
	// live counts the calls still running, so Serve does not return while one is
	// holding a session open.
	live sync.WaitGroup
}

// callState is one in-flight request. The cancel function is kept even when the
// client asked for no progress: a cancellation has to stop the work, not only
// the reports.
type callState struct {
	cancel context.CancelFunc
	prog   *progress
}

// beginCall registers a tools/call and returns a context that a cancellation
// cancels, plus the progress reporter the client asked for.
//
// The two are the same lifetime: a cancelled read has to stop reporting, and a
// finished call must not leave a registration behind for a cancellation that
// arrives late.
func (c *conn) beginCall(m message) (context.Context, *progress) {
	var params struct {
		Meta struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	_ = jsonUnmarshal(m.Params, &params)

	var prog *progress
	if len(params.Meta.ProgressToken) > 0 {
		var token any
		if err := json.Unmarshal(params.Meta.ProgressToken, &token); err != nil {
			token = string(params.Meta.ProgressToken)
		}
		prog = &progress{send: c.notify, token: token}
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.calls[string(m.ID)] = &callState{cancel: cancel, prog: prog}
	c.mu.Unlock()
	return ctx, prog
}

// endCall drops the registration of a finished call and stops its reports.
func (c *conn) endCall(key string, prog *progress) {
	c.mu.Lock()
	cl := c.calls[key]
	delete(c.calls, key)
	c.mu.Unlock()
	if cl != nil {
		cl.cancel()
	}
	prog.close()
}

// notify writes a one-way frame.
func (c *conn) notify(method string, params any) {
	if err := c.enc.write(notification{JSONRPC: "2.0", Method: method, Params: params}); err != nil {
		c.log.logf("write %s: %v", method, err)
	}
}

// cancelCall stops the work of an in-flight call, which unblocks its read and
// ends its reports. An id that is unknown is not an error: a cancellation for a
// request that already answered is allowed to arrive.
func (c *conn) cancelCall(id json.RawMessage) {
	if len(id) == 0 {
		return
	}
	c.mu.Lock()
	cl := c.calls[string(id)]
	c.mu.Unlock()
	if cl == nil {
		return
	}
	cl.cancel()
	cl.prog.close()
}

// cancelAll stops every in-flight call, which happens when the input ends, and
// waits a bounded time for them to finish.
//
// The wait matters: a call that is still running holds the session it works on,
// and closing that session underneath it would leave the call reporting a
// failure that never happened. The bound matters too, because an unbounded wait
// on a call that ignores its context would keep the process alive forever, and a
// client that closed its input expects the server to go away.
func (c *conn) cancelAll() bool {
	c.mu.Lock()
	open := c.calls
	c.calls = map[string]*callState{}
	c.mu.Unlock()
	for _, cl := range open {
		cl.cancel()
		cl.prog.close()
	}
	if len(open) == 0 {
		return true
	}

	done := make(chan struct{})
	go func() {
		c.live.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(shutdownGrace):
		// The remaining calls are left to die with the process. Their sessions
		// are still closed, so the daemon is not left holding a live shell.
		c.log.logf("%d call(s) did not stop within %s", len(open), shutdownGrace)
		return false
	}
}

// encoder writes frames as newline-delimited JSON. One encoder per output stream
// keeps the frames of concurrent calls from interleaving.
type encoder struct {
	mu sync.Mutex
	w  io.Writer
}

func newEncoder(w io.Writer) *encoder { return &encoder{w: w} }

func (e *encoder) write(m any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err = e.w.Write(append(b, '\n'))
	return err
}

// reply answers a request. A nil result with a nil error is not a case: a
// successful call always has a result.
func (c *conn) reply(id json.RawMessage, result any, rerr *wireError) {
	if len(id) == 0 {
		// An error about a frame whose id could not be read is still owed an id,
		// and the specification says null. Omitting the field is not allowed.
		id = json.RawMessage("null")
	}
	m := message{JSONRPC: "2.0", ID: id}
	if rerr != nil {
		m.Error = rerr
	} else {
		b, err := json.Marshal(result)
		if err != nil {
			c.log.logf("marshal reply: %v", err)
			m.Error = &wireError{Code: codeInternal, Message: "this server could not encode the result"}
		} else {
			m.Result = b
		}
	}
	if err := c.enc.write(m); err != nil {
		c.log.logf("write reply: %v", err)
	}
}

// notification is a one-way frame.
type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func jsonUnmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	return nil
}

func errorsAs(err error, target **wireError) bool { return errors.As(err, target) }
