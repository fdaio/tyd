package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// progressInterval is how often a parked read reports progress. It is a variable
// so a test does not have to wait five seconds to see one.
var progressInterval = 5 * time.Second

// progress is one client progress request. The client sends a token with
// tools/call, and the server reports against it while a read is parked, so the
// client's request timer does not fire on a read that is working.
type progress struct {
	mu   sync.Mutex
	send func(method string, params any)
	// token is the client's own progressToken, echoed back verbatim.
	token any
	// closed ends reports for a call that answered or was cancelled.
	closed bool
	// ticks counts the reports sent, so a client can show that the server is
	// still working on the same step.
	ticks int
}

type progressKey struct{}

// report sends one progress notification. Reports are dropped after the call
// ends, so a late tick from an abandoned read does not arrive under a request
// that is already answered.
func (p *progress) report(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.ticks++
	p.send("notifications/progress", map[string]any{
		"progressToken": p.token,
		"progress":      p.ticks,
		"message":       msg,
	})
}

// close ends the reports of a call. A nil reporter is allowed, because a client
// may ask for no progress at all.
func (p *progress) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// progressOf returns the progress reporter a call carries, or nil when the
// client asked for none.
func progressOf(ctx context.Context) func() {
	p, _ := ctx.Value(progressKey{}).(*progress)
	if p == nil {
		return nil
	}
	return func() { p.report("waiting for output") }
}

// reportWhileWaiting runs report every progressInterval until done is closed. A
// parked read is where the wall clock goes, so without this a client timeout
// would fire on a read that is working.
func reportWhileWaiting(report func(), done <-chan struct{}) {
	t := time.NewTicker(progressInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			report()
		}
	}
}

// withProgress returns a context carrying p, so the tool handlers can find it
// without a parameter.
func withProgress(ctx context.Context, p *progress) context.Context {
	return context.WithValue(ctx, progressKey{}, p)
}

// logger writes one line per tool call to stderr. Stdout carries the protocol, so
// a stray line there breaks the stream.
//
// It records what happened and never what the terminal printed: a model reads the
// output, and a log file is a second place it can leak from.
type logger struct {
	mu sync.Mutex
	w  io.Writer
}

func newLogger(w io.Writer) *logger { return &logger{w: w} }

func (l *logger) logf(format string, args ...any) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "tyd mcp: "+format+"\n", args...)
}

// closeOpened ends the sessions this process opened, ignoring failures: the
// process is exiting, and a session that outlives it anyway is the normal case
// unless the flag was given.
func (s *server) closeOpened() {
	if !s.closeOnExit {
		return
	}
	s.mu.Lock()
	keys := append([]string(nil), s.order...)
	states := make([]*sessionState, 0, len(keys))
	for _, k := range keys {
		states = append(states, s.sessions[k])
	}
	s.mu.Unlock()

	// One budget for the whole set, not one per session: a per-session timeout
	// multiplied by the cap is how an exit turns into a wait a client does not
	// expect.
	budget := time.Now().Add(shutdownGrace)
	for _, st := range states {
		if st == nil || !st.openedByUs {
			continue
		}
		left := time.Until(budget)
		if left <= 0 {
			s.logf("close on exit ran out of time with %d session(s) left", len(states))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), left)
		err := s.backend.Close(ctx, st.session)
		cancel()
		if err != nil {
			s.logf("close on exit failed for %s: %v", st.aliasName, err)
			continue
		}
		s.logf("closed %s on exit", st.aliasName)
	}
}

// Serve runs the stdio conversation until the input ends or ctx is done.
//
// The client ends a read with notifications/cancelled, and the process ends with
// the context. A frame this server cannot parse is logged and skipped: one bad
// frame must not take the connection down.
func Serve(ctx context.Context, in io.Reader, out io.Writer, b Backend, logw io.Writer, cfg Options) error {
	log := newLogger(logw)
	srv := newServer(b, log, cfg)
	conn := &conn{enc: newEncoder(out, log), log: log, srv: srv, calls: map[string]*callState{}}
	// The order matters: stop the calls and wait for them, then end the sessions
	// they were working on.
	defer srv.closeOpened()
	defer conn.cancelAll()

	log.logf("serving peers=%s read_only=%t max_sessions=%d close_on_exit=%t",
		strings.Join(srv.peerNames(), ","), cfg.ReadOnly, srv.maxSessions, cfg.CloseOnExit)

	// The input is read on its own goroutine, because a read cannot be
	// interrupted and this server has to be stoppable.
	//
	// The loop below can only see a cancelled context between frames, and the
	// frame it is waiting for is a blocking read. Closing the input on
	// cancellation does not help: with a real process and a real signal, closing
	// the file descriptor a goroutine is blocked on leaves that read blocked,
	// because the kernel still holds the file description open for it. So a
	// terminal would sit there after Ctrl-C.
	//
	// The reader therefore has its own goroutine, and this loop leaves without
	// waiting for it. A reader parked on a read ends when the input closes or
	// when the process does, which is the right cost for a command that is on
	// its way out; an embedder that outlives the call owns closing its input.
	stop := make(chan struct{})
	defer close(stop)

	type incoming struct {
		msg message
		err error
	}
	frames := make(chan incoming)
	read := make(chan struct{})
	go func() {
		defer close(frames)
		// The reader is buffered once. decode framed a new bufio.Reader per frame
		// before, which would have dropped anything the client pipelined behind
		// the frame being read.
		dec := newDecoder(in)
		for {
			msg, err := dec.next()
			select {
			case frames <- incoming{msg: msg, err: err}:
			case <-stop:
				return
			}
			select {
			case <-read:
			case <-stop:
				return
			}
			if err != nil {
				var bad *frameError
				if !errors.As(err, &bad) {
					// End of input, or a read that failed. A frame the decoder
					// can name is skipped and the conversation continues.
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			switch {
			case f.err == nil:
				conn.handle(ctx, f.msg)
			case errors.Is(f.err, errEOF):
				return nil
			default:
				// A frame this server cannot read is answered with a protocol
				// error and then skipped: a client that writes one bad frame
				// still expects the rest of its conversation to work.
				var bad *frameError
				if errors.As(f.err, &bad) {
					conn.reply(bad.id, nil, &wireError{Code: bad.code, Message: bad.Error()})
				} else {
					log.logf("decode: %v", f.err)
				}
			}
			select {
			case read <- struct{}{}:
			case <-stop:
				return nil
			}
		}
	}
}

// handle dispatches one frame. A response frame on the server's input carries no
// method, so it is dropped with a log line instead of being answered.
func (c *conn) handle(ctx context.Context, m message) {
	switch {
	case m.isRequest():
		c.request(ctx, m)
	case m.isNotification():
		c.notification(ctx, m)
	default:
		c.log.logf("dropping a frame with no method: id=%s", string(m.ID))
	}
}

func (c *conn) request(ctx context.Context, m message) {
	if m.Method == "ping" {
		c.reply(m.ID, map[string]any{}, nil)
		return
	}

	callCtx, prog := c.beginCall(m)
	callCtx = withProgress(callCtx, prog)

	// The work runs on its own goroutine. A tools/call can sit on a parked read
	// for thirty seconds, and a client must be able to read the cancellation
	// that ends it while that happens. Frames from one encoder never interleave,
	// so concurrent calls can share the output.
	c.live.Add(1)
	go func() {
		defer c.live.Done()
		defer c.endCall(string(m.ID), prog)
		switch m.Method {
		case "initialize":
			c.initialize(m)
		case "tools/list":
			c.toolsList(m)
		case "tools/call":
			c.toolsCall(callCtx, m)
		default:
			c.reply(m.ID, nil, &wireError{
				Code:    codeMethodNotFound,
				Message: fmt.Sprintf("unknown method %q; this server implements initialize, ping, tools/list and tools/call", m.Method),
			})
		}
	}()
}

func (c *conn) notification(ctx context.Context, m message) {
	if m.Method != "notifications/cancelled" {
		return
	}
	var p cancelledParams
	if err := jsonUnmarshal(m.Params, &p); err != nil {
		return
	}
	c.cancelCall(p.RequestID)
	c.log.logf("cancelled request %s", string(p.RequestID))
}

// initialize answers with the negotiated protocol version and what this server
// can do. The capability list is small on purpose: this server has no resources
// and no prompts, and claiming them would make a client ask.
func (c *conn) initialize(m message) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := jsonUnmarshal(m.Params, &p); err != nil {
		c.reply(m.ID, nil, &wireError{Code: codeInvalidParams, Message: "initialize needs a protocolVersion"})
		return
	}
	version := negotiateVersion(p.ProtocolVersion)
	if version != p.ProtocolVersion {
		c.log.logf("client asked for %s; this server answers %s", p.ProtocolVersion, version)
	}
	c.reply(m.ID, map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "tyd",
			"version": serverVersion,
		},
		"instructions": c.srv.instructions(),
	}, nil)
}

// instructions is what the model reads before it sees any tool list, so it has to
// describe the server it is actually talking to. It is assembled from the same flags
// the tool list is built from, which is why it is a method: a paragraph describing
// tools this server does not have is worse than no paragraph.
func (s *server) instructions() string {
	base := "Shell sessions on a tyd target, driven one at a time per session. " +
		"session_open creates a session and returns its first output; it never attaches, " +
		"so the session stays writable from here. " +
		"Call session_send with an explicit \\n, then session_read or the reply that send returns " +
		"to see what came back. A command that runs long needs session_interrupt, which is Ctrl-C."
	if s.readOnly {
		base += " This server was started read-only: the tools that type, interrupt or close " +
			"a session are not registered, so a person has to take the session over."
	}
	if s.fileRootConfigured {
		base += " This server can also read and write files inside one directory, with file_read " +
			"and file_write, instead of shelling out to cat. Paths are relative to that directory; " +
			"an absolute path is refused. Prefer them over cat for reading and writing a file."
		if !s.readOnly {
			base += " Each file operation is one call and needs one approval, and the approval is " +
				"spent whether or not the operation succeeds — so a failed file_write is not worth " +
				"retrying on its own; its reason says what happened. Pass the digest file_read " +
				"returned as expected_sha256 to be refused if the file changed since."
		}
	}
	return base
}

func (c *conn) toolsList(m message) {
	c.reply(m.ID, map[string]any{"tools": c.srv.definitions()}, nil)
}

func (c *conn) toolsCall(ctx context.Context, m message) {
	var p callParams
	if err := jsonUnmarshal(m.Params, &p); err != nil {
		c.reply(m.ID, nil, &wireError{Code: codeInvalidParams, Message: "tools/call needs a name and arguments"})
		return
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	text, structured, err := c.srv.dispatch(ctx, p.Name, p.Arguments)
	if err != nil {
		// A call the client withdrew gets the reserved code, so it can tell this
		// apart from a tool that failed on its own.
		if errors.Is(ctx.Err(), context.Canceled) {
			c.reply(m.ID, nil, &wireError{Code: codeCancelled, Message: "the client cancelled this call"})
			return
		}
		if msg, ok := ToolError(err); ok {
			// The call was well formed and the target refused it. That is a
			// result the model should read, not a protocol error.
			c.reply(m.ID, toolResult{
				Content: []contentBlock{{Type: "text", Text: msg}},
				IsError: true,
			}, nil)
			c.log.logf("tools/call %s: %s", p.Name, firstLine(msg))
			return
		}
		var we *wireError
		if !errorsAs(err, &we) {
			we = &wireError{Code: codeInternal, Message: err.Error()}
		}
		c.reply(m.ID, nil, we)
		c.log.logf("tools/call %s: %s", p.Name, firstLine(we.Message))
		return
	}

	c.reply(m.ID, toolResult{
		Content:           []contentBlock{{Type: "text", Text: text}},
		StructuredContent: structured,
	}, nil)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
