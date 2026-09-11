package client

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"tyd/internal/auth"
	"tyd/internal/protocol"
)

type Conn struct {
	nc  net.Conn
	wmu sync.Mutex
}

func Dial(socket string, key ed25519.PrivateKey) (*Conn, error) {
	nc, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w (is 'tyd serve' running?)", socket, err)
	}
	c := &Conn{nc: nc}
	if err := c.Authenticate(key); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) Authenticate(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid identity")
	}
	chal, err := c.Recv()
	if err != nil {
		return err
	}
	if chal.Type == protocol.TypeError {
		return fmt.Errorf("%s", chal.Error)
	}
	if chal.Type != protocol.TypeChallenge {
		return fmt.Errorf("expected challenge, got %q", chal.Type)
	}
	if err := c.Send(auth.AuthFrame(key, chal.Data)); err != nil {
		return err
	}
	resp, err := c.Recv()
	if err != nil {
		return err
	}
	if resp.Type == protocol.TypeError {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.Type != protocol.TypeOK {
		return fmt.Errorf("unexpected auth reply %q", resp.Type)
	}
	return nil
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

func rpc(socket string, key ed25519.PrivateKey, req protocol.Frame) (protocol.Frame, error) {
	c, err := Dial(socket, key)
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

func Create(socket string, key ed25519.PrivateKey, opts CreateOpts) (protocol.SessionInfo, error) {
	if opts.Rows == 0 {
		opts.Rows = 24
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	resp, err := rpc(socket, key, protocol.Frame{
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

func List(socket string, key ed25519.PrivateKey) ([]protocol.SessionInfo, error) {
	resp, err := rpc(socket, key, protocol.Frame{Type: protocol.TypeList})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func CloseSession(socket string, key ed25519.PrivateKey, id string) error {
	_, err := rpc(socket, key, protocol.Frame{Type: protocol.TypeClose, SessionID: id})
	return err
}

const detachByte = 0x1c // Ctrl-\

func Attach(socket string, key ed25519.PrivateKey, id string, stdin *os.File, stdout *os.File) error {
	c, err := Dial(socket, key)
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
