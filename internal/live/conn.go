package live

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"tyd/internal/protocol"
)

// Conn is a daemon-side proxy to a live-agent over its unix socket.
type Conn struct {
	conn net.Conn
	mu   sync.Mutex

	out         chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
	sessClosed  bool
	shellExited bool
	exitCode    int
}

// DialAttach connects and takes the exclusive attach slot.
func DialAttach(dir string, rows, cols uint16) (*Conn, []byte, protocol.SessionInfo, error) {
	c, err := dial(dir)
	if err != nil {
		return nil, nil, protocol.SessionInfo{}, err
	}
	if err := protocol.WriteFrame(c.conn, protocol.Frame{
		Type: protocol.TypeAttach,
		Rows: rows,
		Cols: cols,
	}); err != nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, err
	}
	f, err := protocol.ReadFrame(c.conn)
	if err != nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, err
	}
	if f.Type == protocol.TypeError {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, fmt.Errorf("%s", f.Error)
	}
	if f.Type != protocol.TypeAttached || f.Session == nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, fmt.Errorf("unexpected attach reply %q", f.Type)
	}
	go c.readLoop()
	return c, append([]byte(nil), f.Data...), *f.Session, nil
}

// DialWatch connects as a read-only watcher.
func DialWatch(dir string) (*Conn, []byte, protocol.SessionInfo, error) {
	c, err := dial(dir)
	if err != nil {
		return nil, nil, protocol.SessionInfo{}, err
	}
	if err := protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeWatch}); err != nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, err
	}
	f, err := protocol.ReadFrame(c.conn)
	if err != nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, err
	}
	if f.Type == protocol.TypeError {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, fmt.Errorf("%s", f.Error)
	}
	if f.Type != protocol.TypeWatching || f.Session == nil {
		_ = c.conn.Close()
		return nil, nil, protocol.SessionInfo{}, fmt.Errorf("unexpected watch reply %q", f.Type)
	}
	go c.readLoop()
	return c, append([]byte(nil), f.Data...), *f.Session, nil
}

// RequestClose asks the agent to tear down the shell (and exit).
func RequestClose(dir string) error {
	conn, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		KillAgent(dir)
		RemoveDir(dir)
		return nil
	}
	defer conn.Close()
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClose}); err != nil {
		KillAgent(dir)
		RemoveDir(dir)
		return nil
	}
	_, _ = protocol.ReadFrame(conn)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !Alive(dir) {
			RemoveDir(dir)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	KillAgent(dir)
	RemoveDir(dir)
	return nil
}

func dial(dir string) (*Conn, error) {
	nc, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:   nc,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}, nil
}

func (c *Conn) readLoop() {
	defer c.closeOut()
	for {
		f, err := protocol.ReadFrame(c.conn)
		if err != nil {
			return
		}
		switch f.Type {
		case protocol.TypeOutput:
			cp := append([]byte(nil), f.Data...)
			select {
			case c.out <- cp:
			case <-c.closed:
				return
			}
		case protocol.TypeExit:
			c.mu.Lock()
			c.sessClosed = true
			c.exitCode = f.ExitCode
			c.mu.Unlock()
			return
		case protocol.TypeExited:
			// The shell is gone; the session survives and can be attached again.
			c.mu.Lock()
			c.shellExited = true
			c.exitCode = f.ExitCode
			c.mu.Unlock()
			return
		case protocol.TypeDetached, protocol.TypeClosed:
			return
		case protocol.TypeError:
			return
		}
	}
}

// DialRead is a one-shot pull of sequenced output. It does not take the
// attach slot and does not stay connected. A non-zero waitMS parks the read
// until bytes arrive, the wait elapses, or the reply must be returned anyway.
func DialRead(dir string, cursor, epoch uint64, waitMS, idleMS uint32, pattern string, maxBytes uint32) (ReadResult, error) {
	nc, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		return ReadResult{}, err
	}
	defer nc.Close()
	if err := protocol.WriteFrame(nc, protocol.Frame{Type: protocol.TypeRead, Cursor: cursor, Epoch: epoch, WaitMS: waitMS, IdleMS: idleMS, Match: pattern, MaxBytes: maxBytes}); err != nil {
		return ReadResult{}, err
	}
	f, err := protocol.ReadFrame(nc)
	if err != nil {
		return ReadResult{}, err
	}
	if f.Type == protocol.TypeError {
		return ReadResult{}, fmt.Errorf("%s", f.Error)
	}
	if f.Type != protocol.TypeReadResult {
		return ReadResult{}, fmt.Errorf("unexpected read reply %q", f.Type)
	}
	return ReadResult{
		Data:         append([]byte(nil), f.Data...),
		CursorNext:   f.CursorNext,
		Dropped:      f.Dropped,
		AtEnd:        f.AtEnd,
		Epoch:        f.Epoch,
		CursorAhead:  f.CursorAhead,
		Exited:       f.Exited,
		Reason:       f.Reason,
		Echo:         f.Echo,
		Icanon:       f.Icanon,
		AgentVersion: f.AgentVersion,
	}, nil
}

// SendReply is what a send tells the caller: how many bytes landed, and
// where the output was beforehand so the caller can read only what follows.
type SendReply struct {
	Written int
	Cursor  uint64
	Epoch   uint64
	// AgentVersion is what build the agent is. Zero means it did not say, which is
	// an agent older than the field existed.
	AgentVersion int
}

// DialSend injects keystrokes without taking the attach slot.
func DialSend(dir string, data []byte, secret bool) (SendReply, error) {
	nc, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		return SendReply{}, err
	}
	defer nc.Close()
	if err := protocol.WriteFrame(nc, protocol.Frame{Type: protocol.TypeSend, Data: data, Secret: secret}); err != nil {
		return SendReply{}, err
	}
	f, err := protocol.ReadFrame(nc)
	if err != nil {
		return SendReply{}, err
	}
	if f.Type == protocol.TypeError {
		return SendReply{}, fmt.Errorf("%s", f.Error)
	}
	if f.Type != protocol.TypeOK {
		return SendReply{}, fmt.Errorf("unexpected send reply %q", f.Type)
	}
	return SendReply{Written: int(f.CursorNext), Cursor: f.Cursor, Epoch: f.Epoch}, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeWrite, Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Resize(rows, cols uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeResize, Rows: rows, Cols: cols})
}

func (c *Conn) Signal(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeSignal, Signal: name})
}

func (c *Conn) Recv() ([]byte, error) {
	select {
	case b := <-c.out:
		return b, nil
	case <-c.closed:
		select {
		case b := <-c.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	}
}

func (c *Conn) RecvTimeout(d time.Duration) ([]byte, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b := <-c.out:
		return b, nil
	case <-c.closed:
		select {
		case b := <-c.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

// Ended reports whether the agent-side stream is finished.
func (c *Conn) Ended() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// ShellExited reports whether the stream ended because the shell exited while
// the session itself is still alive.
func (c *Conn) ShellExited() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shellExited && !c.sessClosed
}

func (c *Conn) SessionClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessClosed
}

func (c *Conn) ExitCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitCode
}

func (c *Conn) Detach() {
	c.mu.Lock()
	_ = protocol.WriteFrame(c.conn, protocol.Frame{Type: protocol.TypeDetach})
	c.mu.Unlock()
	select {
	case <-c.closed:
	case <-time.After(2 * time.Second):
	}
	_ = c.conn.Close()
	c.closeOut()
}

func (c *Conn) Close() {
	_ = c.conn.Close()
	c.closeOut()
}

func (c *Conn) closeOut() {
	c.closeOnce.Do(func() { close(c.closed) })
}

// FileResult is what a file operation returned. It is a whole frame rather than a
// struct of fields, on purpose — see DialFile.
type FileResult = protocol.Frame

// DialFile forwards one file operation to the agent that holds the session's
// directory descriptor, and returns the agent's answer.
//
// **The frame goes across as it arrived and the answer comes back as it was sent.**
// No field is re-listed in either direction, so none can be dropped by forgetting
// it: the request copy cannot lose the path or the root claim, and the reply cannot
// lose the ID or the digest. Re-listing is how #118's `secret` flag came to be
// nearly fail-open, and the comment on the read path in the server says the same
// thing about a frame rebuilt field by field.
//
// The agent is the authority here. This function validates nothing about the path: a
// root claim arriving from a daemon is a claim, and the agent decides.
func DialFile(dir string, req protocol.Frame) (FileResult, error) {
	if !Alive(dir) {
		return FileResult{}, fmt.Errorf("session has no running agent; file operations need one")
	}
	nc, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		return FileResult{}, err
	}
	defer nc.Close()
	if err := protocol.WriteFrame(nc, req); err != nil {
		return FileResult{}, err
	}
	f, err := protocol.ReadFrame(nc)
	if err != nil {
		return FileResult{}, err
	}
	if f.Type == protocol.TypeError {
		return FileResult{}, fmt.Errorf("%s", f.Error)
	}
	if f.Type != protocol.TypeFileResult {
		return FileResult{}, fmt.Errorf("unexpected file reply %q", f.Type)
	}
	// A result carrying an error is a **failure**, not a result. The agent reports a
	// refusal by setting Error on the result frame rather than by sending TypeError,
	// because one reply per request is the invariant; without this check the refusal
	// came back as a success with no data in it, and the caller recorded it as a
	// successful operation.
	if f.Error != "" {
		return FileResult{}, fmt.Errorf("%s", f.Error)
	}
	// Checked rather than assumed. A reply that arrived without the ID cannot be
	// matched to its request, and a caller that cannot match it waits out a timeout
	// to attribute the failure.
	if f.ID != req.ID {
		return FileResult{}, fmt.Errorf("file reply carried id %q, request was %q", f.ID, req.ID)
	}
	return f, nil
}
