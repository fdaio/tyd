package client

import (
	"bytes"
	"context"
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
	"tyd/internal/live"
	"tyd/internal/protocol"
	"tyd/internal/relay"
	"tyd/internal/transport"
)

type Endpoint struct {
	Kind       transport.Kind
	Address    string
	CertPath   string   // TLS pin via cert file (optional if CertFP set)
	CertFP     string   // TLS pin via SHA-256 fingerprint hex (optional if CertPath set)
	Candidates []string // extra dial addresses tried after Address (peer data-plane)
	RelayURL   string   // dual-NAT fallback after direct candidates fail (first of RelayURLs)
	RelayURLs  []string // ordered relay fallbacks; tried in turn after direct candidates fail
	PeerID     string   // CP daemon id for relay dial
	// PeerPublic is the pinned Ed25519 public key of the peer on the other
	// end. The relay path has no certificate fingerprint to pin (the Control
	// Panel's peer record carries no daemon id), so the peer is authenticated
	// by its channel-binding signature over the inner TLS session instead.
	PeerPublic ed25519.PublicKey
	OnDial     func(addr string)
	// OnObserved reports the peer address the relay observed for the server,
	// e.g. "203.0.113.7:41234" -- post-NAT ground truth rather than the
	// self-reported interface IPs in Candidates. Diagnostic only: the observed
	// address is not dialled (Phase 4b).
	OnObserved     func(addr, relayURL string)
	OnAttach       func()
	OnReady        func()
	OnLeave        func(msg string)
	OnInputIgnored func() // watch: user typed while read-only
}

func (e Endpoint) String() string {
	return transport.Endpoint{Kind: e.Kind, Address: e.Address}.String()
}

type Conn struct {
	nc   net.Conn
	info transport.Info
	wmu  sync.Mutex
}

const (
	defaultDialAttemptTimeout = 12 * time.Second
)

// dialAttemptTimeout caps TCP/TLS/QUIC dial + handshake + auth per address.
// Tests may lower this.
var dialAttemptTimeout = defaultDialAttemptTimeout

func Dial(ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	return DialContext(context.Background(), ep, key)
}

func DialContext(ctx context.Context, ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	relays := ep.relayFallbacks()
	if len(addrs) == 0 && (len(relays) == 0 || strings.TrimSpace(ep.PeerID) == "") {
		return nil, fmt.Errorf("dial: empty address")
	}

	var errs []string
	for _, addr := range addrs {
		if err := ctx.Err(); err != nil {
			return nil, errInterrupted
		}
		if ep.OnDial != nil {
			ep.OnDial(addr)
		}
		try := ep
		try.Address = addr
		try.Candidates = nil
		try.RelayURL = "" // direct only in this loop
		try.RelayURLs = nil
		c, err := dialOnce(ctx, try, key)
		if err == nil {
			return c, nil
		}
		if ctx.Err() != nil || errors.Is(err, errInterrupted) {
			return nil, errInterrupted
		}
		errs = append(errs, err.Error())
	}

	peerID := strings.TrimSpace(ep.PeerID)
	if len(relays) > 0 && peerID != "" {
		for _, relayURL := range relays {
			if err := ctx.Err(); err != nil {
				return nil, errInterrupted
			}
			if ep.OnDial != nil {
				ep.OnDial("relay " + relayURL)
			}
			try := ep
			try.RelayURL = relayURL
			try.RelayURLs = nil
			c, err := dialViaRelay(ctx, try, key)
			if err == nil {
				return c, nil
			}
			if ctx.Err() != nil || errors.Is(err, errInterrupted) {
				return nil, errInterrupted
			}
			errs = append(errs, err.Error())
		}
	}

	return nil, fmt.Errorf("direct dial failed; tried: %s", strings.Join(errs, "; "))
}

// relayFallbacks returns the ordered relay endpoints to try after direct
// candidates fail. RelayURLs wins when set; otherwise a single RelayURL is used
// so existing single-URL callers keep working.
func (e Endpoint) relayFallbacks() []string {
	out := make([]string, 0, len(e.RelayURLs)+1)
	seen := map[string]struct{}{}
	add := func(raw string) {
		u := strings.TrimSpace(raw)
		if u == "" || u == "off" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	for _, u := range e.RelayURLs {
		add(u)
	}
	add(e.RelayURL)
	return out
}

func dialViaRelay(ctx context.Context, ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, dialAttemptTimeout+20*time.Second)
	defer cancel()
	res, err := relay.DialDetailed(attemptCtx, ep.RelayURL, ep.PeerID)
	if err != nil {
		return nil, err
	}
	raw := res.Conn
	if res.Observed != "" && ep.OnObserved != nil {
		// The relay saw the server's post-NAT address. Logged only: whether a
		// direct dial to it would actually connect is not something we can
		// assume, and preferring it is the next step (Phase 4b). Measurement
		// first, so a preference switch is not a connectivity regression.
		ep.OnObserved(res.Observed, ep.RelayURL)
	}
	// The relay is a blind splice, so the session protocol used to cross it in
	// cleartext. Wrap our own leg in TLS before anything else is written, then
	// check that the server on the other end is the peer we paired with and not
	// a relay that re-terminated TLS.
	secure, binder, err := transport.ClientE2E(raw, transport.E2EClientConfig())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := verifyRelayBinding(secure, ep, binder); err != nil {
		_ = secure.Close()
		return nil, err
	}

	nc := transport.Wrap(secure, transport.Info{
		Transport:  transport.KindRelay,
		RemoteAddr: ep.PeerID + "@" + ep.RelayURL,
		TLS:        true,
	})
	c := &Conn{nc: nc, info: nc.Info()}
	if dl, ok := attemptCtx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	authErr := c.AuthenticateBound(key, binder)
	_ = c.SetDeadline(time.Time{})
	if authErr != nil {
		_ = c.Close()
		return nil, authErr
	}
	return c, nil
}

// verifyRelayBinding checks the server's signature over this TLS session
// against the peer public key learned at pairing time.
func verifyRelayBinding(conn net.Conn, ep Endpoint, binder []byte) error {
	if len(ep.PeerPublic) != ed25519.PublicKeySize {
		// No key means this host cannot check who it reached. Telling the user to
		// pair again is only right when the peer really was paired before
		// tyd pinned keys; the pair itself may be sound and the key simply never
		// reached the client, so say what is missing and what to do about it.
		return fmt.Errorf("relay e2e: this host holds no key pinned for peer %s, so the peer behind the "+
			"relay cannot be identified; run 'tyd peer list' to see whether the key is on record, and "+
			"'tyd revoke %s' followed by a fresh 'tyd accept' if it is not", ep.PeerID, ep.PeerID)
	}
	_ = conn.SetDeadline(time.Now().Add(transport.E2EHandshakeTimeout))
	f, err := protocol.ReadFrame(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("relay e2e binding: %w", err)
	}
	if f.Type == protocol.TypeError {
		return fmt.Errorf("relay e2e: %s", f.Error)
	}
	if f.Type != protocol.TypeBound {
		return fmt.Errorf("relay e2e: expected a binding, got %q", f.Type)
	}
	if !bytes.Equal(f.PublicKey, ep.PeerPublic) {
		// A key is on record and the peer answered with a different one. That is
		// a refusal, not a request to pair again, and saying so keeps the two
		// failures apart.
		return fmt.Errorf("relay e2e: the peer behind the relay presented a key that is not the one pinned "+
			"for %s; this connection is refused", ep.PeerID)
	}
	return transport.VerifyPeerBinding(ep.PeerPublic, nil, binder, f.Data)
}

func dialOnce(ctx context.Context, ep Endpoint, key ed25519.PrivateKey) (*Conn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, dialAttemptTimeout)
	defer cancel()

	var (
		nc  transport.Conn
		err error
	)
	switch ep.Kind {
	case transport.KindUnix, "":
		nc, err = transport.DialUnixContext(attemptCtx, ep.Address)
	case transport.KindTLS:
		if ep.CertFP != "" {
			nc, err = transport.DialTLSFingerprintContext(attemptCtx, ep.Address, ep.CertFP)
		} else {
			nc, err = transport.DialTLSContext(attemptCtx, ep.Address, ep.CertPath)
		}
	case transport.KindQUIC:
		if ep.CertFP == "" {
			return nil, fmt.Errorf("quic requires certificate fingerprint")
		}
		nc, err = transport.DialQUICFingerprintContext(attemptCtx, ep.Address, ep.CertFP)
	default:
		return nil, fmt.Errorf("unknown transport %q", ep.Kind)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		hint := "is 'tyd up' running?"
		if ep.Kind == transport.KindTLS || ep.Kind == transport.KindQUIC {
			hint = "is 'tyd up' running on the peer?"
		}
		return nil, fmt.Errorf("%w (%s)", err, hint)
	}
	c := &Conn{nc: nc, info: nc.Info()}
	if dl, ok := attemptCtx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	authErr := c.Authenticate(key)
	_ = c.SetDeadline(time.Time{})
	if authErr != nil {
		_ = c.Close()
		if errors.Is(authErr, context.Canceled) || errors.Is(authErr, context.DeadlineExceeded) {
			return nil, authErr
		}
		// net timeouts from SetDeadline surface as os.ErrDeadlineExceeded / net timeout
		if ne, ok := authErr.(net.Error); ok && ne.Timeout() {
			return nil, fmt.Errorf("auth %s: %w", ep, authErr)
		}
		return nil, authErr
	}
	return c, nil
}

func DialUnix(socket string, key ed25519.PrivateKey) (*Conn, error) {
	return Dial(Endpoint{Kind: transport.KindUnix, Address: socket}, key)
}

func (c *Conn) Info() transport.Info { return c.info }

// AuthenticateBound is Authenticate with the signature also covering a channel
// binding. On the relay the binding is the inner TLS exporter, so the server
// can tell this auth belongs to this connection.
func (c *Conn) AuthenticateBound(key ed25519.PrivateKey, binder []byte) error {
	return c.authenticate(key, binder)
}

func (c *Conn) Authenticate(key ed25519.PrivateKey) error {
	return c.authenticate(key, nil)
}

func (c *Conn) authenticate(key ed25519.PrivateKey, binder []byte) error {
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
	if err := c.Send(auth.AuthFrameBound(key, chal.Data, binder)); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), dialAttemptTimeout)
	defer cancel()
	return rpcContext(ctx, ep, key, req)
}

func rpcContext(ctx context.Context, ep Endpoint, key ed25519.PrivateKey, req protocol.Frame) (protocol.Frame, error) {
	c, err := DialContext(ctx, ep, key)
	if err != nil {
		return protocol.Frame{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(dialAttemptTimeout))
	}
	defer c.SetDeadline(time.Time{})
	if err := c.Send(req); err != nil {
		return protocol.Frame{}, err
	}
	resp, err := c.Recv()
	if err != nil {
		return protocol.Frame{}, err
	}
	if resp.Type == protocol.TypeError {
		return resp, fmt.Errorf("%s", resp.Error)
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	resp, err := rpcContext(ctx, ep, key, protocol.Frame{
		Type:  protocol.TypeCreate,
		Rows:  opts.Rows,
		Cols:  opts.Cols,
		Shell: opts.Shell,
		Cwd:   opts.Cwd,
	})
	if err != nil {
		return protocol.SessionInfo{}, asInterrupted(err)
	}
	if resp.Session == nil {
		return protocol.SessionInfo{}, fmt.Errorf("create: empty session")
	}
	return *resp.Session, nil
}

// IsRetryableDial reports whether err looks like a stale/unreachable endpoint
// worth refreshing from the Control Panel.
func IsRetryableDial(err error) bool {
	if err == nil || errors.Is(err, errInterrupted) {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"connection refused",
		"i/o timeout",
		"deadline exceeded",
		"no route to host",
		"network is unreachable",
		"direct dial failed",
		"connection reset",
		"broken pipe",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
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

// Read pulls one page of sequenced session output. It does not take the
// exclusive attach slot. The reply is raw PTY bytes; cursor_next pages.
// Pass epoch 0 on the first pull, then the epoch from the last read_result.
// A non-zero wait parks the read until bytes arrive or the wait elapses.
func Read(ep Endpoint, key ed25519.PrivateKey, sessionID string, cursor, epoch uint64, wait time.Duration, cond live.ReadConditions) (protocol.Frame, error) {
	resp, err := rpc(ep, key, protocol.Frame{
		Type:      protocol.TypeRead,
		SessionID: sessionID,
		Cursor:    cursor,
		Epoch:     epoch,
		WaitMS:    uint32(wait / time.Millisecond),
		IdleMS:    cond.IdleMS,
		Match:     cond.Match,
		MaxBytes:  cond.MaxBytes,
	})
	if err != nil {
		return protocol.Frame{}, err
	}
	if resp.Type != protocol.TypeReadResult {
		return protocol.Frame{}, fmt.Errorf("unexpected read reply %q", resp.Type)
	}
	return resp, nil
}

// SendReply is what a send reports: how many bytes landed, and the output
// position from before the write, so a caller can read only what its own
// keystrokes produced.
type SendReply struct {
	Written int
	Cursor  uint64
	Epoch   uint64
}

// Send injects keystrokes without taking the exclusive attach slot. It needs
// the write capability but not attach. An error means nothing was written.
func Send(ep Endpoint, key ed25519.PrivateKey, sessionID string, data []byte) (SendReply, error) {
	resp, err := rpc(ep, key, protocol.Frame{
		Type:      protocol.TypeSend,
		SessionID: sessionID,
		Data:      data,
	})
	// A send that timed out or was preempted still reports how many bytes
	// reached the PTY, so the caller can resume from there instead of
	// resending what already landed.
	reply := SendReply{Written: int(resp.CursorNext), Cursor: resp.Cursor, Epoch: resp.Epoch}
	if err != nil {
		return reply, err
	}
	if resp.Type != protocol.TypeOK {
		return reply, fmt.Errorf("unexpected send reply %q", resp.Type)
	}
	return reply, nil
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

// drainWait bounds how long one half of a finished watch waits for the other.
const drainWait = 500 * time.Millisecond

var (
	errUserDetach   = errors.New("detached")
	errSessionEnded = errors.New("session ended")
	errInterrupted  = errors.New("interrupted")
)

// ErrShellExited reports that the session shell exited but the session itself
// is still alive, so it can be attached again.
var ErrShellExited = errors.New("shell exited")

// IsShellExited reports whether err means the shell exited while the session
// survived.
func IsShellExited(err error) bool { return errors.Is(err, ErrShellExited) }

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
	if errors.Is(err, ErrShellExited) {
		return "shell exited"
	}
	if errors.Is(err, errInterrupted) {
		return "interrupted"
	}
	return "detaching"
}

func asInterrupted(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errInterrupted) || errors.Is(err, context.Canceled) {
		return errInterrupted
	}
	return err
}

func Watch(ep Endpoint, key ed25519.PrivateKey, id string, stdin *os.File, stdout *os.File) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := DialContext(ctx, ep, key)
	if err != nil {
		return asInterrupted(err)
	}
	defer c.Close()
	go closeOnDone(ctx, c)

	if ep.OnAttach != nil {
		ep.OnAttach()
	}

	if err := c.Send(protocol.Frame{Type: protocol.TypeWatch, SessionID: id}); err != nil {
		return asInterrupted(err)
	}
	_ = c.SetDeadline(time.Now().Add(dialAttemptTimeout))
	resp, err := c.Recv()
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		return asInterrupted(err)
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

	restore := func() {}
	fd := -1
	if stdin != nil && term.IsTerminal(int(stdin.Fd())) {
		fd = int(stdin.Fd())
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		restore = func() { _ = term.Restore(fd, old) }
		defer restore()
		drainPendingInput(stdin)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- copyOutput(c, stdout)
	}()
	if stdin != nil {
		go func() {
			errCh <- watchInput(c, stdin, ep.OnInputIgnored)
		}()
	} else {
		// No stdin (tests): stop on SIGINT/SIGQUIT like before.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGQUIT)
		defer signal.Stop(sigCh)
		go func() {
			<-sigCh
			_ = c.Send(protocol.Frame{Type: protocol.TypeDetach})
			errCh <- errUserDetach
		}()
	}

	err = <-errCh
	if errors.Is(err, errUserDetach) {
		// The input side is done (stdin closed or the user asked to detach) and
		// has already sent the detach frame, so the peer is about to end the
		// stream. Give the output side a moment to finish instead of closing
		// the connection now: the history and any exit notice may still be in
		// flight, and cutting the connection would drop them. The wait is
		// bounded because the detach may have come from the output side, with
		// the input side still parked on a terminal that never types.
		select {
		case second := <-errCh:
			if second != nil && !errors.Is(second, errUserDetach) {
				err = second
			} else {
				err = nil
			}
		case <-time.After(drainWait):
			err = nil
		}
	}
	_ = c.Close()
	if stdin != nil {
		_ = stdin.SetReadDeadline(time.Now())
		select {
		case second := <-errCh:
			if err == nil {
				err = second
			}
		case <-time.After(drainWait):
		}
		_ = stdin.SetReadDeadline(time.Time{})
	}
	restore()
	if ep.OnLeave != nil {
		ep.OnLeave(leaveMessage(err))
	}
	return attachStopError(err)
}

const interruptByte = 0x03 // Ctrl-C in raw mode

// watchInput consumes local keystrokes without forwarding them to the session.
// Ctrl-C / Ctrl-\ stop watching; other input triggers a rate-limited hint.
func watchInput(c *Conn, stdin *os.File, onIgnored func()) error {
	buf := make([]byte, 64)
	var lastHint time.Time
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				if b == detachByte || b == interruptByte {
					_ = c.Send(protocol.Frame{Type: protocol.TypeDetach})
					return errUserDetach
				}
			}
			if onIgnored != nil && time.Since(lastHint) >= 2*time.Second {
				lastHint = time.Now()
				onIgnored()
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

func Attach(ep Endpoint, key ed25519.PrivateKey, id string, stdin *os.File, stdout *os.File) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := DialContext(ctx, ep, key)
	if err != nil {
		return asInterrupted(err)
	}
	defer c.Close()
	go closeOnDone(ctx, c)

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
	}

	if err := c.Send(req); err != nil {
		return asInterrupted(err)
	}
	_ = c.SetDeadline(time.Now().Add(dialAttemptTimeout))
	resp, err := c.Recv()
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		return asInterrupted(err)
	}
	if resp.Type == protocol.TypeError {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.Type != protocol.TypeAttached {
		return fmt.Errorf("unexpected attach reply %q", resp.Type)
	}

	// Log readiness while still cooked so verbose lines are not staircase-
	// indented (raw mode treats \n as LF without CR).
	if ep.OnReady != nil {
		ep.OnReady()
	}

	// Keep the terminal cooked until attach succeeds so Ctrl-C stays SIGINT.
	if term.IsTerminal(fd) {
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		restore = func() { _ = term.Restore(fd, old) }
		defer restore()
		drainPendingInput(stdin)
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

func closeOnDone(ctx context.Context, c *Conn) {
	<-ctx.Done()
	if c != nil {
		_ = c.Close()
	}
}

// drainPendingInput discards bytes already buffered on stdin (usually Enter
// pressed while waiting to connect).
//
// Terminals typically do not support SetReadDeadline; calling Read after a
// failed deadline would block forever. Use non-blocking reads on TTYs.
func drainPendingInput(stdin *os.File) {
	if stdin == nil {
		return
	}
	fd := int(stdin.Fd())
	if term.IsTerminal(fd) {
		drainNonblock(fd)
		return
	}
	if err := stdin.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		drainNonblock(fd)
		return
	}
	defer stdin.SetReadDeadline(time.Time{})
	buf := make([]byte, 256)
	for {
		n, err := stdin.Read(buf)
		if n == 0 || err != nil {
			return
		}
	}
}

func drainNonblock(fd int) {
	if err := syscall.SetNonblock(fd, true); err != nil {
		return
	}
	defer func() { _ = syscall.SetNonblock(fd, false) }()
	buf := make([]byte, 256)
	for {
		n, err := syscall.Read(fd, buf)
		if n <= 0 || err != nil {
			return
		}
	}
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
		case protocol.TypeExited:
			return ErrShellExited
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
