package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/live"
	"tyd/internal/procs"
	"tyd/internal/protocol"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// DefaultApprovalTTL bounds how long a pending attach request, and an
// operator approval for it, stay valid.
const DefaultApprovalTTL = 10 * time.Minute

const (
	// MaxSendBytes caps one send. The frame limit is larger, but a send
	// writes straight into the PTY, so a single call stays modest.
	MaxSendBytes = 64 << 10
	// MaxReadWait caps the server-side wait. A parked read holds a
	// connection and a goroutine, so a client cannot ask for an open end.
	MaxReadWait = 30 * time.Second
)

type Config struct {
	Socket       string
	Listen       string // empty/off = no manual TLS; e.g. 127.0.0.1:61211
	DataListen   string // empty/off = no data-plane QUIC; e.g. 127.0.0.1:0
	CertPath     string
	KeyPath      string
	Mgr          *session.Manager
	Trust        *auth.Store
	ApprovalMode string // full|pre|post; default full

	// Audit receives control events in every approval mode. Nil means stderr
	// under post and no auditing otherwise.
	Audit audit.Sink
	// SessionIdleTimeout closes DETACHED sessions left unattended for this
	// long. Zero (default) never reaps.
	SessionIdleTimeout time.Duration
	// ApprovalTTL bounds pending attach requests and approvals.
	// Zero uses DefaultApprovalTTL.
	ApprovalTTL time.Duration
}

// PendingApproval is a remote attach waiting for a local decision.
type PendingApproval struct {
	SessionID  string
	Principal  string
	Transport  string
	RemoteAddr string
	Requested  time.Time
}

type Server struct {
	cfg Config

	mu            sync.Mutex
	listeners     []net.Listener
	conns         map[string]*connState
	tlsCertFP     string                    // full hex fingerprint (shared cert)
	tlsListenAddr string                    // manual --listen actual addr
	dataPlaneAddr string                    // data-plane actual listen addr
	pending       map[string]*pendingAttach // gate key -> waiting request
	approved      map[string]time.Time      // gate key -> one-shot approval expiry
	createdBy     map[string]string         // gated session id -> requester public key
	stopReaper    chan struct{}
	reaperOnce    sync.Once
}

type pendingAttach struct {
	sessionID  string
	principal  string
	transport  string
	remoteAddr string
	at         time.Time
}

func New(socket string, mgr *session.Manager, trust *auth.Store) *Server {
	return NewWithConfig(Config{Socket: socket, Mgr: mgr, Trust: trust})
}

func NewWithConfig(cfg Config) *Server {
	mode, _ := controlpanel.NormalizeApproval(cfg.ApprovalMode)
	cfg.ApprovalMode = mode
	if cfg.Audit == nil {
		if mode == controlpanel.ApprovalPost {
			cfg.Audit = StderrAudit()
		} else {
			cfg.Audit = audit.Discard()
		}
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = DefaultApprovalTTL
	}
	s := &Server{
		cfg:        cfg,
		conns:      make(map[string]*connState),
		pending:    make(map[string]*pendingAttach),
		approved:   make(map[string]time.Time),
		createdBy:  make(map[string]string),
		stopReaper: make(chan struct{}),
	}
	if cfg.Mgr != nil {
		cfg.Mgr.SetOnClosed(func(info session.ClosedInfo) {
			s.audit(audit.Event{
				Kind:      audit.KindClose,
				SessionID: info.SessionID,
				Principal: info.Principal,
				PeerID:    info.PeerID,
				CreatedAt: info.CreatedAt.UTC().Format(time.RFC3339),
				Time:      info.ClosedAt,
			})
		})
	}
	return s
}

// StderrAudit writes JSON Lines to stderr, for daemons without an audit file.
func StderrAudit() audit.Sink {
	return audit.FuncSink(func(e audit.Event) {
		if e.Time.IsZero() {
			e.Time = time.Now()
		}
		e.Time = e.Time.UTC()
		b, err := json.Marshal(e)
		if err != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "audit %s\n", b)
	})
}

func (s *Server) audit(e audit.Event) {
	if s.cfg.Audit == nil {
		return
	}
	if e.Approval == "" {
		e.Approval = s.approvalMode()
	}
	s.cfg.Audit.Log(e)
}

func (s *Server) connEvent(st *connState, kind audit.Kind) audit.Event {
	name := ""
	if st.principal != nil {
		name = st.principal.Name
	}
	return audit.Event{
		Kind:       kind,
		Principal:  name,
		Transport:  string(st.info.Transport),
		RemoteAddr: st.info.RemoteAddr,
	}
}

// gated reports whether this connection must get local approval before it may
// create a session or look at one. Unix means the local operator.
func (s *Server) gated(st *connState) bool {
	return s.approvalMode() == controlpanel.ApprovalPre && st.info.Transport != transport.KindUnix
}

func gateKey(sessionID string, p *auth.Principal) string {
	if p == nil {
		return sessionID + "|"
	}
	return sessionID + "|" + auth.EncodePublic(p.Pub)
}

// consumeApproval spends a one-shot approval for this session and principal.
func (s *Server) consumeApproval(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.approved[key]
	if !ok {
		return false
	}
	delete(s.approved, key)
	return time.Now().Before(exp)
}

// requestApproval records a waiting attach so the operator can approve it.
func (s *Server) requestApproval(st *connState, sessionID string) {
	req := &pendingAttach{
		sessionID:  sessionID,
		transport:  string(st.info.Transport),
		remoteAddr: st.info.RemoteAddr,
		at:         time.Now().UTC(),
	}
	if st.principal != nil {
		req.principal = st.principal.Name
	}
	s.mu.Lock()
	s.pending[gateKey(sessionID, st.principal)] = req
	s.mu.Unlock()

	e := s.connEvent(st, audit.KindAttachPending)
	e.SessionID = sessionID
	s.audit(e)
	fmt.Fprintf(os.Stderr, "tyd approval needed: %s wants session %s (tyd session approve %s)\n",
		req.principal, sessionID, sessionID)
}

// PendingApprovals lists attach requests still waiting for a decision.
func (s *Server) PendingApprovals() []PendingApproval {
	now := time.Now()
	s.mu.Lock()
	out := make([]PendingApproval, 0, len(s.pending))
	for key, req := range s.pending {
		if now.Sub(req.at) > s.cfg.ApprovalTTL {
			delete(s.pending, key)
			// A request that times out is a denial, and the record of it belongs
			// in the log: otherwise a peer can wait out the TTL and then attach
			// with nothing in the audit trail about the attempt.
			e := audit.Event{
				Time:       now.UTC(),
				Kind:       audit.KindApprovalExpired,
				SessionID:  req.sessionID,
				Principal:  req.principal,
				Transport:  req.transport,
				RemoteAddr: req.remoteAddr,
				Reason:     "no decision before the approval timeout",
			}
			s.audit(e)
			continue
		}
		out = append(out, PendingApproval{
			SessionID:  req.sessionID,
			Principal:  req.principal,
			Transport:  req.transport,
			RemoteAddr: req.remoteAddr,
			Requested:  req.at,
		})
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID != out[j].SessionID {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].Principal < out[j].Principal
	})
	return out
}

// grantRequesterAttach lets whoever asked for a gated session attach once, so
// approving a create does not immediately ask again for the attach that
// follows it. Later reattaches are reviewed again.
func (s *Server) grantRequesterAttach(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, ok := s.createdBy[sessionID]
	if !ok {
		return
	}
	delete(s.createdBy, sessionID)
	s.approved[sessionID+"|"+pub] = time.Now().Add(s.cfg.ApprovalTTL)
}

// forgetSession drops gate bookkeeping for a session that is gone.
func (s *Server) forgetSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.createdBy, sessionID)
	for key, req := range s.pending {
		if req.sessionID == sessionID {
			delete(s.pending, key)
		}
	}
	for key := range s.approved {
		if strings.HasPrefix(key, sessionID+"|") {
			delete(s.approved, key)
		}
	}
}

// decidePending approves or drops every waiting request for a session and
// reports how many were decided.
func (s *Server) decidePending(sessionID string, approve bool) int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, req := range s.pending {
		if req.sessionID != sessionID {
			continue
		}
		delete(s.pending, key)
		if now.Sub(req.at) > s.cfg.ApprovalTTL {
			s.audit(audit.Event{
				Time:       now.UTC(),
				Kind:       audit.KindApprovalExpired,
				SessionID:  sessionID,
				Principal:  req.principal,
				Transport:  req.transport,
				RemoteAddr: req.remoteAddr,
				Reason:     "no decision before the approval timeout",
			})
			continue
		}
		if approve {
			s.approved[key] = now.Add(s.cfg.ApprovalTTL)
		}
		n++
	}
	return n
}

func (s *Server) approvalMode() string {
	if s.cfg.ApprovalMode == "" {
		return controlpanel.ApprovalFull
	}
	return s.cfg.ApprovalMode
}

func (s *Server) Start() error {
	if s.cfg.Trust == nil {
		return fmt.Errorf("trust store required")
	}
	if s.cfg.Socket != "" {
		ln, err := transport.ListenUnix(s.cfg.Socket)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.mu.Unlock()
		go s.accept(ln)
	}
	if s.cfg.Listen != "" && s.cfg.Listen != "off" {
		ln, fp, err := transport.ListenTLS(s.cfg.Listen, s.cfg.CertPath, s.cfg.KeyPath)
		if err != nil {
			_ = s.Close()
			return err
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.tlsCertFP = fp
		s.tlsListenAddr = ln.Addr().String()
		s.mu.Unlock()
		go s.accept(ln)
	}
	if s.cfg.DataListen != "" && s.cfg.DataListen != "off" {
		ln, fp, err := transport.ListenQUIC(s.cfg.DataListen, s.cfg.CertPath, s.cfg.KeyPath)
		if err != nil {
			_ = s.Close()
			return err
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.tlsCertFP = fp
		s.dataPlaneAddr = ln.Addr().String()
		s.mu.Unlock()
		go s.accept(ln)
	}
	s.mu.Lock()
	n := len(s.listeners)
	s.mu.Unlock()
	if n == 0 {
		return fmt.Errorf("no listeners configured")
	}
	if s.cfg.SessionIdleTimeout > 0 && s.cfg.Mgr != nil {
		go s.reapIdleLoop(s.cfg.SessionIdleTimeout)
	}
	return nil
}

func reapInterval(idle time.Duration) time.Duration {
	step := idle / 4
	if step > 30*time.Second {
		step = 30 * time.Second
	}
	if step < 100*time.Millisecond {
		step = 100 * time.Millisecond
	}
	return step
}

func (s *Server) reapIdleLoop(idle time.Duration) {
	tick := time.NewTicker(reapInterval(idle))
	defer tick.Stop()
	for {
		select {
		case <-s.stopReaper:
			return
		case now := <-tick.C:
			for _, id := range s.cfg.Mgr.ReapIdle(idle, now) {
				s.audit(audit.Event{
					Kind:      audit.KindIdleClose,
					SessionID: id,
					Reason:    fmt.Sprintf("idle for %s", idle),
				})
				fmt.Fprintf(os.Stderr, "tyd closed idle session %s (idle %s)\n", id, idle)
			}
		}
	}
}

func (s *Server) TLSFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return transport.ShortFP(s.tlsCertFP)
}

// TLSFingerprintFull returns the full SHA-256 hex fingerprint of the TLS cert.
func (s *Server) TLSFingerprintFull() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsCertFP
}

func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsListenAddr
}

func (s *Server) DataPlaneAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dataPlaneAddr
}

func (s *Server) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c, nil, connFromSession(c))
	}
}

// ServeConn runs the tyd session protocol on an already-accepted connection
// (e.g. a relay splice). It blocks until the connection ends.
func (s *Server) ServeConn(conn net.Conn, binder []byte) {
	s.handle(conn, binder, false)
}

func (s *Server) Close() error {
	s.reaperOnce.Do(func() { close(s.stopReaper) })
	s.mu.Lock()
	lns := s.listeners
	s.listeners = nil
	s.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	s.cfg.Mgr.Shutdown()
	return nil
}

type connState struct {
	id        string
	conn      net.Conn
	wmu       sync.Mutex
	att       *session.Attachment
	watcher   *session.Watcher
	sid       string
	principal *auth.Principal
	// fromSession marks a connection whose peer process is inside a tyd session
	// on this host. Such a connection may read but not change anything.
	fromSession bool
	// binder is the relay path's inner-TLS channel binding. The auth response
	// must cover it, or a relay could authenticate one connection on the
	// client's behalf using a response taken from another.
	binder  []byte
	info    transport.Info
	state   string
	started time.Time
}

func (c *connState) send(f protocol.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return protocol.WriteFrame(c.conn, f)
}

func (s *Server) handle(conn net.Conn, binder []byte, fromSession bool) {
	info := transport.Info{Transport: transport.KindUnix}
	if tc, ok := conn.(transport.Conn); ok {
		info = tc.Info()
	} else if conn.LocalAddr() != nil {
		info.LocalAddr = conn.LocalAddr().String()
		info.RemoteAddr = conn.RemoteAddr().String()
	}
	st := &connState{
		id:          newConnID(),
		conn:        conn,
		binder:      binder,
		fromSession: fromSession,
		info:        info,
		state:       "handshaking",
		started:     time.Now().UTC(),
	}
	s.mu.Lock()
	s.conns[st.id] = st
	s.mu.Unlock()

	defer func() {
		if st.att != nil {
			st.att.Detach()
			st.att = nil
		}
		if st.watcher != nil {
			st.watcher.Close()
			st.watcher = nil
		}
		s.mu.Lock()
		delete(s.conns, st.id)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	if err := s.handshake(st); err != nil {
		_ = st.send(protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
		return
	}
	st.state = "authenticated"

	for {
		f, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		if err := s.dispatch(st, f); err != nil {
			_ = st.send(protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
		}
	}
}

// sessionOriginRefusal explains why a control command was refused. The wording
// matters: the caller is usually an agent, and "not allowed" without a reason
// invites a retry loop.
func sessionOriginRefusal(what string) error {
	return fmt.Errorf("%s is refused for a process inside a tyd session: this session shares the "+
		"daemon's user and home, so it could approve its own request or turn approval off. "+
		"Approve it from a terminal outside the session. This is a speed bump, not a boundary; "+
		"see docs/security.md", what)
}

// connFromSession reports whether a freshly accepted local connection came from
// a process inside a tyd session on this host, so the dispatch layer can refuse
// control commands from it.
//
// This is the check the environment marker cannot be: a process that clears
// TYD_SESSION still has a pid, and on Linux the kernel reports the peer of a unix
// socket without anyone having to trust the other side. Where the platform
// cannot answer (macOS: peer credentials report the user, not the pid) this
// returns false and only the CLI-side guard applies.
func connFromSession(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var (
		pid    int
		hasPid bool
	)
	if err := raw.Control(func(fd uintptr) { pid, hasPid = peerPID(fd) }); err != nil {
		return false
	}
	if !hasPid || pid <= 0 {
		return false
	}
	inSession, err := procs.DescendantOfSession(pid)
	if err != nil {
		return false
	}
	return inSession
}

func newConnID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handshake(st *connState) error {
	nonce, err := auth.NewNonce()
	if err != nil {
		return err
	}
	if err := st.send(auth.ChallengeFrame(nonce)); err != nil {
		return err
	}
	f, err := protocol.ReadFrame(st.conn)
	if err != nil {
		return err
	}
	if f.Type != protocol.TypeAuth {
		return fmt.Errorf("authentication required")
	}
	p, err := s.cfg.Trust.AuthenticateBound(nonce, st.binder, f.PublicKey, f.Data)
	if err != nil {
		return err
	}
	st.principal = p
	return st.send(protocol.Frame{Type: protocol.TypeOK})
}

func (s *Server) require(st *connState, cap auth.Cap, sessionID string) error {
	if !s.cfg.Trust.Allow(st.principal, cap, sessionID) {
		e := s.connEvent(st, audit.KindDenied)
		e.SessionID = sessionID
		e.Capability = string(cap)
		s.audit(e)
		return auth.Denied(cap)
	}
	return nil
}

// gateAttach enforces pre-approval for a remote attach or watch. The first
// request is recorded for the operator; the approval it grants is one-shot, so
// every later remote look at the session is reviewed again.
func (s *Server) gateAttach(st *connState, sessionID string) error {
	if !s.gated(st) {
		return nil
	}
	if s.consumeApproval(gateKey(sessionID, st.principal)) {
		return nil
	}
	s.requestApproval(st, sessionID)
	return fmt.Errorf("attach pending approval; ask the operator to run: tyd session approve %s", sessionID)
}

// auditRead records a read that broke the client's view of the stream: the
// cursor was reset, or the requested prefix was already gone. A plain page is
// not recorded. Draining the disk cap is a thousand calls and the chain does
// not rotate, so one event per page would bury the attach it belongs to.
func (s *Server) auditRead(st *connState, sessionID string, cursorAhead bool, dropped uint64) {
	reason := ""
	switch {
	case cursorAhead:
		reason = "cursor_reset"
	case dropped > 0:
		reason = "dropped_prefix"
	default:
		return
	}
	e := s.connEvent(st, audit.KindRead)
	e.SessionID = sessionID
	e.Reason = reason
	s.audit(e)
}

// auditSend records that bytes were injected. The count goes in, never the
// bytes: the chain stays free of terminal content.
func (s *Server) auditSend(st *connState, sessionID string, n int) {
	e := s.connEvent(st, audit.KindSend)
	e.SessionID = sessionID
	e.Bytes = n
	s.audit(e)
}

func (s *Server) Connections() []protocol.ConnInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]protocol.ConnInfo, 0, len(s.conns))
	for _, c := range s.conns {
		name := ""
		if c.principal != nil {
			name = c.principal.Name
		}
		out = append(out, protocol.ConnInfo{
			ID:            c.id,
			Transport:     string(c.info.Transport),
			LocalAddr:     c.info.LocalAddr,
			RemoteAddr:    c.info.RemoteAddr,
			TLS:           c.info.TLS,
			CertFP:        c.info.CertFP,
			State:         c.state,
			Principal:     name,
			SessionID:     c.sid,
			EstablishedAt: c.started.Format(time.RFC3339),
		})
	}
	return out
}

func (s *Server) dispatch(st *connState, f protocol.Frame) error {
	switch f.Type {
	case protocol.TypeCreate:
		if err := s.require(st, auth.CapCreate, ""); err != nil {
			return err
		}
		opts := session.CreateOpts{
			Rows:     f.Rows,
			Cols:     f.Cols,
			Shell:    f.Shell,
			Cwd:      f.Cwd,
			Owner:    st.principal.Name,
			OwnerPub: auth.EncodePublic(st.principal.Pub),
			PeerID:   st.principal.Name,
		}
		var (
			sess *session.Session
			err  error
		)
		gated := s.gated(st)
		if gated {
			sess, err = s.cfg.Mgr.CreatePending(opts)
		} else {
			sess, err = s.cfg.Mgr.Create(opts)
		}
		if err != nil {
			return err
		}
		if err := s.cfg.Trust.Grant(st.principal.Pub, sess.ID, auth.OwnerCaps...); err != nil {
			_ = s.cfg.Mgr.Close(sess.ID)
			return err
		}
		kind := audit.KindCreate
		if gated {
			kind = audit.KindCreatePending
			s.mu.Lock()
			s.createdBy[sess.ID] = auth.EncodePublic(st.principal.Pub)
			s.mu.Unlock()
		}
		e := s.connEvent(st, kind)
		e.SessionID = sess.ID
		s.audit(e)
		info := sess.Info()
		return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})

	case protocol.TypeApprove:
		if st.fromSession {
			return sessionOriginRefusal("approve")
		}
		if st.info.Transport != transport.KindUnix {
			return fmt.Errorf("approve only allowed on unix")
		}
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.require(st, auth.CapCreate, ""); err != nil {
			return err
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		if sess.State() != session.StatePending {
			if n := s.decidePending(f.SessionID, true); n == 0 {
				return fmt.Errorf("session %s has nothing waiting for approval", f.SessionID)
			}
			e := s.connEvent(st, audit.KindApprove)
			e.SessionID = f.SessionID
			e.Reason = "attach"
			s.audit(e)
			info := sess.Info()
			return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})
		}
		sess, err = s.cfg.Mgr.Approve(f.SessionID)
		if err != nil {
			return err
		}
		s.grantRequesterAttach(f.SessionID)
		e := s.connEvent(st, audit.KindApprove)
		e.SessionID = f.SessionID
		e.Reason = "create"
		s.audit(e)
		info := sess.Info()
		return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})

	case protocol.TypeReject:
		if st.fromSession {
			return sessionOriginRefusal("reject")
		}
		if st.info.Transport != transport.KindUnix {
			return fmt.Errorf("reject only allowed on unix")
		}
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.require(st, auth.CapCreate, ""); err != nil {
			return err
		}
		if n := s.decidePending(f.SessionID, false); n > 0 {
			e := s.connEvent(st, audit.KindReject)
			e.SessionID = f.SessionID
			e.Reason = "attach"
			s.audit(e)
			return st.send(protocol.Frame{Type: protocol.TypeOK})
		}
		if err := s.cfg.Mgr.Reject(f.SessionID); err != nil {
			return err
		}
		s.forgetSession(f.SessionID)
		e := s.connEvent(st, audit.KindReject)
		e.SessionID = f.SessionID
		e.Reason = "create"
		s.audit(e)
		return st.send(protocol.Frame{Type: protocol.TypeOK})

	case protocol.TypeList:
		if err := s.require(st, auth.CapList, ""); err != nil {
			return err
		}
		return st.send(protocol.Frame{Type: protocol.TypeSessions, Sessions: s.cfg.Mgr.List()})

	case protocol.TypeStatus:
		if err := s.require(st, auth.CapList, ""); err != nil {
			return err
		}
		return st.send(protocol.Frame{Type: protocol.TypeConnections, Connections: s.Connections()})

	case protocol.TypeClose:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.require(st, auth.CapClose, f.SessionID); err != nil {
			return err
		}
		if err := s.cfg.Mgr.Close(f.SessionID); err != nil {
			return err
		}
		s.forgetSession(f.SessionID)
		return st.send(protocol.Frame{Type: protocol.TypeClosed})

	case protocol.TypeAttach:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if st.att != nil || st.watcher != nil {
			return fmt.Errorf("connection already attached")
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		if err := s.require(st, auth.CapAttach, f.SessionID); err != nil {
			return err
		}
		if err := s.gateAttach(st, f.SessionID); err != nil {
			return err
		}
		att, snap, err := sess.Attach()
		if err != nil {
			return err
		}
		if f.Rows > 0 && f.Cols > 0 && s.cfg.Trust.Allow(st.principal, auth.CapResize, f.SessionID) {
			_ = att.Resize(f.Rows, f.Cols)
		}
		st.att = att
		st.sid = f.SessionID
		st.state = "attached"
		e := s.connEvent(st, audit.KindAttach)
		e.SessionID = f.SessionID
		s.audit(e)
		info := sess.Info()
		if err := st.send(protocol.Frame{Type: protocol.TypeAttached, Session: &info}); err != nil {
			att.Detach()
			st.att = nil
			st.sid = ""
			st.state = "authenticated"
			return err
		}
		if len(snap) > 0 {
			if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: snap}); err != nil {
				att.Detach()
				st.att = nil
				st.sid = ""
				st.state = "authenticated"
				return err
			}
		}
		go s.pumpOutput(st, att)
		return nil

	case protocol.TypeWatch:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if st.att != nil || st.watcher != nil {
			return fmt.Errorf("connection already attached")
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		if err := s.require(st, auth.CapAttach, f.SessionID); err != nil {
			return err
		}
		if err := s.gateAttach(st, f.SessionID); err != nil {
			return err
		}
		w, snap, err := sess.Watch()
		if err != nil {
			return err
		}
		info := sess.Info()
		if err := st.send(protocol.Frame{Type: protocol.TypeWatching, Session: &info}); err != nil {
			w.Close()
			return err
		}
		if len(snap) > 0 {
			if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: snap}); err != nil {
				w.Close()
				return err
			}
		}
		if info.State == string(session.StateClosed) {
			_ = st.send(protocol.Frame{Type: protocol.TypeExit, ExitCode: w.ExitCode()})
			w.Close()
			return nil
		}
		st.watcher = w
		st.sid = f.SessionID
		st.state = "watching"
		e2 := s.connEvent(st, audit.KindAttach)
		e2.SessionID = f.SessionID
		e2.Reason = "watch"
		s.audit(e2)
		go s.pumpWatchOutput(st, w)
		return nil

	case protocol.TypeRead:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		if err := s.require(st, auth.CapAttach, f.SessionID); err != nil {
			return err
		}
		if err := s.gateAttach(st, f.SessionID); err != nil {
			return err
		}
		wait := time.Duration(f.WaitMS) * time.Millisecond
		if wait > MaxReadWait {
			wait = MaxReadWait
		}
		res, err := sess.Read(f.Cursor, f.Epoch, wait, live.ReadConditions{
			IdleMS:   f.IdleMS,
			Match:    f.Match,
			MaxBytes: f.MaxBytes,
		})
		if err != nil {
			return err
		}
		s.auditRead(st, f.SessionID, res.CursorAhead, res.Dropped)
		return st.send(protocol.Frame{
			Type:        protocol.TypeReadResult,
			Data:        res.Data,
			CursorNext:  res.CursorNext,
			Dropped:     res.Dropped,
			AtEnd:       res.AtEnd,
			Epoch:       res.Epoch,
			CursorAhead: res.CursorAhead,
			Exited:      res.Exited,
			Reason:      res.Reason,
		})

	case protocol.TypeSend:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if len(f.Data) == 0 {
			return fmt.Errorf("send requires data")
		}
		if len(f.Data) > MaxSendBytes {
			return fmt.Errorf("send is limited to %d bytes", MaxSendBytes)
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		if err := s.require(st, auth.CapWrite, f.SessionID); err != nil {
			return err
		}
		// send reads session output through the same path as read, so it is
		// gated the same way. The approval is spent once, at the start of the
		// request, and is not re-checked while a read waits.
		if err := s.gateAttach(st, f.SessionID); err != nil {
			return err
		}
		rep, err := sess.Send(f.Data)
		if err != nil {
			return err
		}
		s.auditSend(st, f.SessionID, rep.Written)
		return st.send(protocol.Frame{
			Type:       protocol.TypeOK,
			CursorNext: uint64(rep.Written),
			Cursor:     rep.Cursor,
			Epoch:      rep.Epoch,
		})

	case protocol.TypeWrite:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		if err := s.require(st, auth.CapWrite, st.sid); err != nil {
			return err
		}
		_, err := st.att.Write(f.Data)
		return err

	case protocol.TypeResize:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		if err := s.require(st, auth.CapResize, st.sid); err != nil {
			return err
		}
		return st.att.Resize(f.Rows, f.Cols)

	case protocol.TypeSignal:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		if err := s.require(st, auth.CapSignal, st.sid); err != nil {
			return err
		}
		return st.att.Signal(f.Signal)

	case protocol.TypeDetach:
		if st.att != nil {
			st.att.Detach()
			st.att = nil
			e := s.connEvent(st, audit.KindDetach)
			e.SessionID = st.sid
			s.audit(e)
			st.sid = ""
			st.state = "authenticated"
			return st.send(protocol.Frame{Type: protocol.TypeDetached})
		}
		if st.watcher != nil {
			st.watcher.Close()
			st.watcher = nil
			e := s.connEvent(st, audit.KindDetach)
			e.SessionID = st.sid
			e.Reason = "watch"
			s.audit(e)
			st.sid = ""
			st.state = "authenticated"
			return st.send(protocol.Frame{Type: protocol.TypeDetached})
		}
		return fmt.Errorf("not attached")

	default:
		return fmt.Errorf("unknown type %q", f.Type)
	}
}

func (s *Server) pumpOutput(st *connState, att *session.Attachment) {
	for {
		b, err := att.Recv()
		if err != nil {
			s.sendStreamEnd(st, att.SessionClosed(), att.ShellExited(), att.ExitCode())
			return
		}
		if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: b}); err != nil {
			att.Detach()
			return
		}
	}
}

func (s *Server) pumpWatchOutput(st *connState, w *session.Watcher) {
	for {
		b, err := w.Recv()
		if err != nil {
			s.sendStreamEnd(st, w.SessionClosed(), w.ShellExited(), w.ExitCode())
			return
		}
		if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: b}); err != nil {
			w.Close()
			return
		}
	}
}

// sendStreamEnd tells the client why an output stream finished. A closed
// session is final; an exited shell is not, so the session stays attachable.
func (s *Server) sendStreamEnd(st *connState, closed, shellExited bool, code int) {
	switch {
	case closed:
		_ = st.send(protocol.Frame{Type: protocol.TypeExit, ExitCode: code})
	case shellExited:
		_ = st.send(protocol.Frame{Type: protocol.TypeExited, ExitCode: code})
	}
}
