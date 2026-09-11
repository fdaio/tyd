package client

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"tyd/internal/protocol"
)

type Conn struct {
	nc  net.Conn
	wmu sync.Mutex
}

func Dial(socket string) (*Conn, error) {
	nc, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w (is 'tyd serve' running?)", socket, err)
	}
	return &Conn{nc: nc}, nil
}

func (c *Conn) Close() error {
	return c.nc.Close()
}

func (c *Conn) Send(f protocol.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return protocol.WriteFrame(c.nc, f)
}

func (c *Conn) Recv() (protocol.Frame, error) {
	return protocol.ReadFrame(c.nc)
}

func (c *Conn) SetDeadline(d time.Time) error {
	return c.nc.SetDeadline(d)
}

func rpc(socket string, req protocol.Frame) (protocol.Frame, error) {
	c, err := Dial(socket)
	if err != nil {
		return protocol.Frame{}, err
	}
	defer c.Close()
	if err := c.Send(req); err != nil {
		return protocol.Frame{}, err
	}
	resp, err := c.Recv()
	if err != nil {
		return protocol.Frame{}, err
	}
	if resp.Type == protocol.TypeError {
		return protocol.Frame{}, fmt.Errorf("%s", resp.Error)
	}
	return resp, nil
}

type CreateOpts struct {
	Rows  uint16
	Cols  uint16
	Shell string
	Cwd   string
}

func Create(socket string, opts CreateOpts) (protocol.SessionInfo, error) {
	if opts.Rows == 0 {
		opts.Rows = 24
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	resp, err := rpc(socket, protocol.Frame{
		Type:  protocol.TypeCreate,
		Rows:  opts.Rows,
		Cols:  opts.Cols,
		Shell: opts.Shell,
		Cwd:   opts.Cwd,
	})
	if err != nil {
		return protocol.SessionInfo{}, err
	}
	if resp.Session == nil {
		return protocol.SessionInfo{}, fmt.Errorf("create: empty session")
	}
	return *resp.Session, nil
}

func List(socket string) ([]protocol.SessionInfo, error) {
	resp, err := rpc(socket, protocol.Frame{Type: protocol.TypeList})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func CloseSession(socket, id string) error {
	_, err := rpc(socket, protocol.Frame{Type: protocol.TypeClose, SessionID: id})
	return err
}

const detachByte = 0x1c // Ctrl-\

func Attach(socket, id string, stdin *os.File, stdout *os.File) error {
	c, err := Dial(socket)
	if err != nil {
		return err
	}
	defer c.Close()

	req := protocol.Frame{Type: protocol.TypeAttach, SessionID: id}
	restore := func() {}
	fd := int(stdin.Fd())
	if term.IsTerminal(fd) {
		cols, rows, err := term.GetSize(fd)
		if err == nil {
			req.Rows = uint16(rows)
			req.Cols = uint16(cols)
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		restore = func() { _ = term.Restore(fd, old) }
		defer restore()
	}

	if err := c.Send(req); err != nil {
		return err
	}
	resp, err := c.Recv()
	if err != nil {
		return err
	}
	if resp.Type == protocol.TypeError {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.Type != protocol.TypeAttached {
		return fmt.Errorf("unexpected attach reply %q", resp.Type)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- copyOutput(c, stdout)
	}()
	go func() {
		errCh <- copyInput(c, stdin)
	}()

	if term.IsTerminal(fd) {
		winCh := make(chan os.Signal, 1)
		signal.Notify(winCh, syscall.SIGWINCH)
		defer signal.Stop(winCh)
		go func() {
			for range winCh {
				cols, rows, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				_ = c.Send(protocol.Frame{Type: protocol.TypeResize, Rows: uint16(rows), Cols: uint16(cols)})
			}
		}()
	}

	err = <-errCh
	_ = c.Close()
	_ = stdin.SetReadDeadline(time.Now())
	select {
	case <-errCh:
	case <-time.After(500 * time.Millisecond):
	}
	restore()
	_ = stdin.SetReadDeadline(time.Time{})
	return err
}

func copyOutput(c *Conn, stdout *os.File) error {
	for {
		f, err := c.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch f.Type {
		case protocol.TypeOutput:
			if _, err := stdout.Write(f.Data); err != nil {
				return err
			}
		case protocol.TypeExit:
			return nil
		case protocol.TypeDetached:
			return nil
		case protocol.TypeError:
			return fmt.Errorf("%s", f.Error)
		}
	}
}

func copyInput(c *Conn, stdin *os.File) error {
	buf := make([]byte, 1024)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			data := buf[:n]
			for i, b := range data {
				if b == detachByte {
					if i > 0 {
						if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: data[:i]}); err != nil {
							return err
						}
					}
					if err := c.Send(protocol.Frame{Type: protocol.TypeDetach}); err != nil {
						return err
					}
					return nil
				}
			}
			if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: append([]byte(nil), data...)}); err != nil {
				return err
			}
		}
		if err != nil {
			_ = c.Send(protocol.Frame{Type: protocol.TypeDetach})
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func WaitSocket(socket string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.Dial("unix", socket)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("socket %s not ready", socket)
}
