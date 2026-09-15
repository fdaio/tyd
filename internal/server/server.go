package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/session"
	"tyd/internal/transport"
)

type Config struct {
	Socket     string
	Listen     string // empty/off = no manual TLS; e.g. 127.0.0.1:61211
	DataListen string // empty/off = no data-plane TLS; e.g. 127.0.0.1:0
	CertPath   string
	KeyPath    string
	Mgr        *session.Manager
	Trust      *auth.Store
}

type Server struct {
	cfg Config

	mu            sync.Mutex
	listeners     []net.Listener
	conns         map[string]*connState
	tlsCertFP     string // full hex fingerprint (shared cert)
	tlsListenAddr string // manual --listen actual addr
	dataPlaneAddr string // data-plane actual listen addr
}

func New(socket string, mgr *session.Manager, trust *auth.Store) *Server {
	return NewWithConfig(Config{Socket: socket, Mgr: mgr, Trust: trust})
}

func NewWithConfig(cfg Config) *Server {
	return &Server{
		cfg:   cfg,
		conns: make(map[string]*connState),
	}
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
		ln, fp, err := transport.ListenTLS(s.cfg.DataListen, s.cfg.CertPath, s.cfg.KeyPath)
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
	return nil
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
		go s.handle(c)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	lns := s.listeners
	s.listeners = nil
	s.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	s.cfg.Mgr.CloseAll()
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
	info      transport.Info
	state     string
	started   time.Time
}

func (c *connState) send(f protocol.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return protocol.WriteFrame(c.conn, f)
}

func (s *Server) handle(conn net.Conn) {
	info := transport.Info{Transport: transport.KindUnix}
	if tc, ok := conn.(transport.Conn); ok {
		info = tc.Info()
	} else if conn.LocalAddr() != nil {
		info.LocalAddr = conn.LocalAddr().String()
		info.RemoteAddr = conn.RemoteAddr().String()
	}
	st := &connState{
		id:      newConnID(),
		conn:    conn,
		info:    info,
		state:   "handshaking",
		started: time.Now().UTC(),
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
	p, err := s.cfg.Trust.Authenticate(nonce, f.PublicKey, f.Data)
	if err != nil {
		return err
	}
	st.principal = p
	return st.send(protocol.Frame{Type: protocol.TypeOK})
}

func (s *Server) require(st *connState, cap auth.Cap, sessionID string) error {
	if !s.cfg.Trust.Allow(st.principal, cap, sessionID) {
		return auth.Denied(cap)
	}
	return nil
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
		sess, err := s.cfg.Mgr.Create(session.CreateOpts{
			Rows:  f.Rows,
			Cols:  f.Cols,
			Shell: f.Shell,
			Cwd:   f.Cwd,
			Owner: st.principal.Name,
		})
		if err != nil {
			return err
		}
		if err := s.cfg.Trust.Grant(st.principal.Pub, sess.ID, auth.OwnerCaps...); err != nil {
			_ = s.cfg.Mgr.Close(sess.ID)
			return err
		}
		info := sess.Info()
		return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})

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
		return st.send(protocol.Frame{Type: protocol.TypeClosed})

	case protocol.TypeAttach:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.require(st, auth.CapAttach, f.SessionID); err != nil {
			return err
		}
		if st.att != nil || st.watcher != nil {
			return fmt.Errorf("connection already attached")
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
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
		if err := s.require(st, auth.CapAttach, f.SessionID); err != nil {
			return err
		}
		if st.att != nil || st.watcher != nil {
			return fmt.Errorf("connection already attached")
		}
		sess, err := s.cfg.Mgr.Get(f.SessionID)
		if err != nil {
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
		go s.pumpWatchOutput(st, w)
		return nil

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
			st.sid = ""
			st.state = "authenticated"
			return st.send(protocol.Frame{Type: protocol.TypeDetached})
		}
		if st.watcher != nil {
			st.watcher.Close()
			st.watcher = nil
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
			if att.SessionClosed() {
				_ = st.send(protocol.Frame{Type: protocol.TypeExit, ExitCode: att.ExitCode()})
			}
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
			if w.SessionClosed() {
				_ = st.send(protocol.Frame{Type: protocol.TypeExit, ExitCode: w.ExitCode()})
			}
			return
		}
		if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: b}); err != nil {
			w.Close()
			return
		}
	}
}
