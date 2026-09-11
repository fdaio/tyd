package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"tyd/internal/protocol"
	"tyd/internal/session"
)

type Server struct {
	Socket string
	Mgr    *session.Manager

	mu sync.Mutex
	ln net.Listener
}

func New(socket string, mgr *session.Manager) *Server {
	return &Server{Socket: socket, Mgr: mgr}
}

func (s *Server) Start() error {
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
	conn net.Conn
	wmu  sync.Mutex
	att  *session.Attachment
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

func (s *Server) dispatch(st *connState, f protocol.Frame) error {
	switch f.Type {
	case protocol.TypeCreate:
		sess, err := s.Mgr.Create(session.CreateOpts{
			Rows:  f.Rows,
			Cols:  f.Cols,
			Shell: f.Shell,
			Cwd:   f.Cwd,
		})
		if err != nil {
			return err
		}
		info := sess.Info()
		return st.send(protocol.Frame{Type: protocol.TypeOK, Session: &info})

	case protocol.TypeList:
		return st.send(protocol.Frame{Type: protocol.TypeSessions, Sessions: s.Mgr.List()})

	case protocol.TypeClose:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
		}
		if err := s.Mgr.Close(f.SessionID); err != nil {
			return err
		}
		return st.send(protocol.Frame{Type: protocol.TypeClosed})

	case protocol.TypeAttach:
		if f.SessionID == "" {
			return fmt.Errorf("session_id required")
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
		if f.Rows > 0 && f.Cols > 0 {
			_ = att.Resize(f.Rows, f.Cols)
		}
		st.att = att
		info := sess.Info()
		if err := st.send(protocol.Frame{Type: protocol.TypeAttached, Session: &info}); err != nil {
			att.Detach()
			st.att = nil
			return err
		}
		if len(snap) > 0 {
			if err := st.send(protocol.Frame{Type: protocol.TypeOutput, Data: snap}); err != nil {
				att.Detach()
				st.att = nil
				return err
			}
		}
		go s.pumpOutput(st, att)
		return nil

	case protocol.TypeWrite:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		_, err := st.att.Write(f.Data)
		return err

	case protocol.TypeResize:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		return st.att.Resize(f.Rows, f.Cols)

	case protocol.TypeSignal:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		return st.att.Signal(f.Signal)

	case protocol.TypeDetach:
		if st.att == nil {
			return fmt.Errorf("not attached")
		}
		st.att.Detach()
		st.att = nil
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
