package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/session"
)

type Server struct {
	Socket string
	Mgr    *session.Manager
	Trust  *auth.Store

	mu sync.Mutex
	ln net.Listener
}

func New(socket string, mgr *session.Manager, trust *auth.Store) *Server {
	return &Server{Socket: socket, Mgr: mgr, Trust: trust}
}

func (s *Server) Start() error {
	if s.Trust == nil {
		return fmt.Errorf("trust store required")
	}
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0o700); err != nil {
		return err
	}
	_ = os.Remove(s.Socket)
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.Socket, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go s.accept()
	return nil
}

func (s *Server) accept() {
	for {
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	_ = os.Remove(s.Socket)
	s.Mgr.CloseAll()
	return nil
}

type connState struct {
	conn      net.Conn
	wmu       sync.Mutex
	att       *session.Attachment
	sid       string
	principal *auth.Principal
}

func (c *connState) send(f protocol.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return protocol.WriteFrame(c.conn, f)
}

func (s *Server) handle(conn net.Conn) {
	st := &connState{conn: conn}
	defer func() {
		if st.att != nil {
			st.att.Detach()
			st.att = nil
		}
		_ = conn.Close()
	}()

	if err := s.handshake(st); err != nil {
		_ = st.send(protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
		return
	}

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
	p, err := s.Trust.Authenticate(nonce, f.PublicKey, f.Data)
	if err != nil {
		return err
	}
	st.principal = p
	return st.send(protocol.Frame{Type: protocol.TypeOK})
}

func (s *Server) require(st *connState, cap auth.Cap, sessionID string) error {
	if !s.Trust.Allow(st.principal, cap, sessionID) {
		return auth.Denied(cap)
	}
	return nil
}

func (s *Server) dispatch(st *connState, f protocol.Frame) error {
	switch f.Type {
	case protocol.TypeCreate:
		if err := s.require(st, auth.CapCreate, ""); err != nil {
			return err
		}
		sess, err := s.Mgr.Create(session.CreateOpts{
			Rows:  f.Rows,
			Cols:  f.Cols,
			Shell: f.Shell,
			Cwd:   f.Cwd,
			Owner: st.principal.Name,
		})
		if err != nil {
			return err
		}
		if err := s.Trust.Grant(st.principal.Pub, sess.ID, auth.OwnerCaps...); err != nil {
			_ = s.Mgr.Close(sess.ID)
			return err
		}
		info := sess.Info()
		return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})

	case protocol.TypeList:
		if err := s.require(st, auth.CapList, ""); err != nil {
			return err
		}
		return st.send(protocol.Frame{Type: protocol.TypeSessions, Sessions: s.Mgr.List()})

	case protocol.TypeClose:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.require(st, auth.CapClose, f.SessionID); err != nil {
			return err
		}
		if err := s.Mgr.Close(f.SessionID); err != nil {
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
		if st.att != nil {
			return fmt.Errorf("connection already attached")
		}
		sess, err := s.Mgr.Get(f.SessionID)
		if err != nil {
			return err
		}
		att, snap, err := sess.Attach()
		if err != nil {
			return err
		}
		if f.Rows > 0 && f.Cols > 0 && s.Trust.Allow(st.principal, auth.CapResize, f.SessionID) {
			_ = att.Resize(f.Rows, f.Cols)
		}
		st.att = att
		st.sid = f.SessionID
		info := sess.Info()
		if err := st.send(protocol.Frame{Type: protocol.TypeAttached, Session: &info}); err != nil {
			att.Detach()
			st.att = nil
			st.sid = ""
			return err
		}
		if len(snap) > 0 {
			if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: snap}); err != nil {
				att.Detach()
				st.att = nil
				st.sid = ""
				return err
			}
		}
		go s.pumpOutput(st, att)
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
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		st.att.Detach()
		st.att = nil
		st.sid = ""
		return st.send(protocol.Frame{Type: protocol.TypeDetached})

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
