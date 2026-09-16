package client

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/transport"
)

type Endpoint struct {
	Kind       transport.Kind
	Address    string
	CertPath   string   // TLS pin via cert file (optional if CertFP set)
	CertFP     string   // TLS pin via SHA-256 fingerprint hex (optional if CertPath set)
	Candidates []string // extra dial addresses tried after Address (peer data-plane)
	OnDial     func(addr string)
	OnAttach   func()
	OnReady    func()
	OnLeave    func(msg string)
}

func (e Endpoint) String() string {
	return transport.Endpoint{Kind: e.Kind, Address: e.Address}.String()
}

type Conn struct {
	nc   net.Conn
	info transport.Info
	wmu  sync.Mutex
}

func Dial(ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	addrs := make([]string, 0, 1+len(ep.Candidates))
	if strings.TrimSpace(ep.Address) != "" {
		addrs = append(addrs, ep.Address)
	}
	seen := map[string]struct{}{}
	for _, a := range addrs {
		seen[a] = struct{}{}
	}
	for _, a := range ep.Candidates {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dial: empty address")
	}

	var errs []string
	for _, addr := range addrs {
		if ep.OnDial != nil {
			ep.OnDial(addr)
		}
		try := ep
		try.Address = addr
		try.Candidates = nil
		c, err := dialOnce(try, key)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
	}
	return nil, fmt.Errorf("direct dial failed; tried: %s", strings.Join(errs, "; "))
}

func dialOnce(ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	var (
		nc  transport.Conn
		err error
	)
	switch ep.Kind {
	case transport.KindUnix, "":
		nc, err = transport.DialUnix(ep.Address)
	case transport.KindTLS:
		if ep.CertFP != "" {
			nc, err = transport.DialTLSFingerprint(ep.Address, ep.CertFP)
		} else {
			nc, err = transport.DialTLS(ep.Address, ep.CertPath)
		}
	case transport.KindQUIC:
		if ep.CertFP == "" {
			return nil, fmt.Errorf("quic requires certificate fingerprint")
		}
		nc, err = transport.DialQUICFingerprint(ep.Address, ep.CertFP)
	default:
		return nil, fmt.Errorf("unknown transport %q", ep.Kind)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w (is 'tyd up' running on the peer?)", ep, err)
	}
	c := &Conn{nc: nc, info: nc.Info()}
	if err := c.Authenticate(key); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func DialUnix(socket string, key ed25519.PrivateKey) (*Conn, error) {
	return Dial(Endpoint{Kind: transport.KindUnix, Address: socket}, key)
}

func (c *Conn) Info() transport.Info { return c.info }

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

func rpc(ep Endpoint, key ed25519.PrivateKey, req protocol.Frame) (protocol.Frame, error) {
	c, err := Dial(ep, key)
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

func Create(ep Endpoint, key ed25519.PrivateKey, opts CreateOpts) (protocol.SessionInfo, error) {
	if opts.Rows == 0 {
		opts.Rows = 24
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	resp, err := rpc(ep, key, protocol.Frame{
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

func List(ep Endpoint, key ed25519.PrivateKey) ([]protocol.SessionInfo, error) {
	resp, err := rpc(ep, key, protocol.Frame{Type: protocol.TypeList})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func Status(ep Endpoint, key ed25519.PrivateKey) ([]protocol.ConnInfo, error) {
	resp, err := rpc(ep, key, protocol.Frame{Type: protocol.TypeStatus})
	if err != nil {
		return nil, err
	}
	return resp.Connections, nil
}

func CloseSession(ep Endpoint, key ed25519.PrivateKey, id string) error {
	_, err := rpc(ep, key, protocol.Frame{Type: protocol.TypeClose, SessionID: id})
	return err
}

func Approve(ep Endpoint, key ed25519.PrivateKey, id string) (protocol.SessionInfo, error) {
	resp, err := rpc(ep, key, protocol.Frame{Type: protocol.TypeApprove, SessionID: id})
	if err != nil {
		return protocol.SessionInfo{}, err
	}
	if resp.Session == nil {
		return protocol.SessionInfo{}, fmt.Errorf("approve: empty session")
	}
	return *resp.Session, nil
}

func Reject(ep Endpoint, key ed25519.PrivateKey, id string) error {
	_, err := rpc(ep, key, protocol.Frame{Type: protocol.TypeReject, SessionID: id})
	return err
}

const detachByte = 0x1c // Ctrl-\

var (
	errUserDetach   = errors.New("detached")
	errSessionEnded = errors.New("session ended")
)

func attachStopError(err error) error {
	if err == nil || errors.Is(err, errUserDetach) || errors.Is(err, errSessionEnded) {
		return nil
	}
	return err
}

func leaveMessage(err error) string {
	if errors.Is(err, errSessionEnded) {
		return "session ended"
	}
	return "detaching"
}

func Watch(ep Endpoint, key ed25519.PrivateKey, id string, stdout *os.File) error {
	c, err := Dial(ep, key)
	if err != nil {
		return err
	}
	defer c.Close()
	if ep.OnAttach != nil {
		ep.OnAttach()
	}

	if err := c.Send(protocol.Frame{Type: protocol.TypeWatch, SessionID: id}); err != nil {
		return err
	}
	resp, err := c.Recv()
	if err != nil {
		return err
	}
	if resp.Type == protocol.TypeError {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.Type != protocol.TypeWatching && resp.Type != protocol.TypeAttached {
		return fmt.Errorf("unexpected watch reply %q", resp.Type)
	}
	if ep.OnReady != nil {
		ep.OnReady()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Stop(sigCh)

	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- copyOutput(c, stdout)
		close(done)
	}()
	go func() {
		select {
		case <-sigCh:
			_ = c.Send(protocol.Frame{Type: protocol.TypeDetach})
		case <-done:
		}
	}()

	err = <-errCh
	_ = c.Close()
	if ep.OnLeave != nil {
		ep.OnLeave(leaveMessage(err))
	}
	return attachStopError(err)
}

func Attach(ep Endpoint, key ed25519.PrivateKey, id string, stdin *os.File, stdout *os.File) error {
	c, err := Dial(ep, key)
	if err != nil {
		return err
	}
	defer c.Close()
	if ep.OnAttach != nil {
		ep.OnAttach()
	}

	req := protocol.Frame{Type: protocol.TypeAttach, SessionID: id}
	restore := func() {}
	fd := int(stdin.Fd())
	var lastCols, lastRows uint16
	if term.IsTerminal(fd) {
		cols, rows, err := term.GetSize(fd)
		if err == nil {
			req.Rows = uint16(rows)
			req.Cols = uint16(cols)
			lastCols, lastRows = req.Cols, req.Rows
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		restore = func() { _ = term.Restore(fd, old) }
		defer restore()
		// Drop Enter/keys typed while connecting so they don't spam the remote shell.
		drainPendingInput(stdin)
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
	if ep.OnReady != nil {
		ep.OnReady()
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- copyOutput(c, stdout)
	}()
	go func() {
		errCh <- copyInput(c, stdin)
	}()

	if term.IsTerminal(fd) {
		winCh := make(chan os.Signal, 4)
		signal.Notify(winCh, syscall.SIGWINCH)
		defer signal.Stop(winCh)
		// MakeRaw often synthesizes SIGWINCH; ignore no-op resizes that reprint the prompt.
		drainSignals(winCh)
		go func() {
			for range winCh {
				cols, rows, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				c16, r16 := uint16(cols), uint16(rows)
				if c16 == lastCols && r16 == lastRows {
					continue
				}
				lastCols, lastRows = c16, r16
				_ = c.Send(protocol.Frame{Type: protocol.TypeResize, Rows: r16, Cols: c16})
			}
		}()
	}

	err = <-errCh
	_ = c.Close()
	_ = stdin.SetReadDeadline(time.Now())
	select {
	case second := <-errCh:
		if err == nil {
			err = second
		}
	case <-time.After(500 * time.Millisecond):
	}
	restore()
	_ = stdin.SetReadDeadline(time.Time{})
	if ep.OnLeave != nil {
		ep.OnLeave(leaveMessage(err))
	}
	return attachStopError(err)
}

// drainPendingInput discards bytes already buffered on stdin (usually Enter
// pressed while waiting to connect).
func drainPendingInput(stdin *os.File) {
	if stdin == nil {
		return
	}
	_ = stdin.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	buf := make([]byte, 256)
	for {
		n, err := stdin.Read(buf)
		if n == 0 || err != nil {
			break
		}
	}
	_ = stdin.SetReadDeadline(time.Time{})
}

func drainSignals(ch <-chan os.Signal) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
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
			return errSessionEnded
		case protocol.TypeDetached:
			return errUserDetach
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
					return errUserDetach
				}
			}
			if err := c.Send(protocol.Frame{Type: protocol.TypeWrite, Data: append([]byte(nil), data...)}); err != nil {
				return err
			}
		}
		if err != nil {
			_ = c.Send(protocol.Frame{Type: protocol.TypeDetach})
			if err == io.EOF {
				return errUserDetach
			}
			return err
		}
	}
}

func WaitReady(ep Endpoint, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var (
			c   transport.Conn
			err error
		)
		switch ep.Kind {
		case transport.KindTLS:
			if ep.CertFP != "" {
				c, err = transport.DialTLSFingerprint(ep.Address, ep.CertFP)
			} else {
				c, err = transport.DialTLS(ep.Address, ep.CertPath)
			}
		case transport.KindQUIC:
			c, err = transport.DialQUICFingerprint(ep.Address, ep.CertFP)
		default:
			c, err = transport.DialUnix(ep.Address)
		}
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("endpoint %s not ready", ep)
}

// WaitSocket keeps the old helper for unix-only tests.
func WaitSocket(socket string, timeout time.Duration) error {
	return WaitReady(Endpoint{Kind: transport.KindUnix, Address: socket}, timeout)
}
