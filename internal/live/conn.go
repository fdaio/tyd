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
// attach slot and does not stay connected.
func DialRead(dir string, cursor uint64) (ReadResult, error) {
	nc, err := net.DialTimeout("unix", SockPath(dir), time.Second)
	if err != nil {
		return ReadResult{}, err
	}
	defer nc.Close()
	if err := protocol.WriteFrame(nc, protocol.Frame{Type: protocol.TypeRead, Cursor: cursor}); err != nil {
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
		Data:       append([]byte(nil), f.Data...),
		CursorNext: f.CursorNext,
		Dropped:    f.Dropped,
		AtEnd:      f.AtEnd,
	}, nil
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
