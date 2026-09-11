package session

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"tyd/internal/protocol"
)

type State string

const (
	StateAttached State = "ATTACHED"
	StateDetached State = "DETACHED"
	StateClosed   State = "CLOSED"
)

const ringMax = 64 << 10

type CreateOpts struct {
	Rows  uint16
	Cols  uint16
	Shell string
	Cwd   string
	Env   []string
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session)}
}

func (m *Manager) Create(opts CreateOpts) (*Session, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	s, err := startSession(id, opts)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *Manager) Get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

func (m *Manager) List() []protocol.SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.Info())
	}
	return out
}

func (m *Manager) Close(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session %s not found", id)
	}
	delete(m.sessions, id)
	m.mu.Unlock()
	return s.Close()
}

func (m *Manager) CloseAll() {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for id, s := range m.sessions {
		all = append(all, s)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, s := range all {
		_ = s.Close()
	}
}

type Session struct {
	ID        string
	Owner     string
	User      string
	CreatedAt time.Time

	mu        sync.Mutex
	state     State
	rows      uint16
	cols      uint16
	cmd       *exec.Cmd
	pty       *os.File
	attach    *Attachment
	ring      []byte
	exitCode  int
	closed    bool
	closeOnce sync.Once
	cmdDone   chan struct{}
}

type Attachment struct {
	s         *Session
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func startSession(id string, opts CreateOpts) (*Session, error) {
	if opts.Rows == 0 {
		opts.Rows = 24
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	if opts.Shell == "" {
		opts.Shell = defaultShell()
	}
	cmd := exec.Command(opts.Shell)
	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	} else if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	if len(opts.Env) > 0 {
		cmd.Env = opts.Env
	} else {
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	}

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: opts.Rows, Cols: opts.Cols})
	if err != nil {
		return nil, fmt.Errorf("start pty: %w", err)
	}

	owner := ""
	if u, err := user.Current(); err == nil {
		owner = u.Username
	}

	s := &Session{
		ID:        id,
		Owner:     owner,
		User:      owner,
		CreatedAt: time.Now().UTC(),
		state:     StateDetached,
		rows:      opts.Rows,
		cols:      opts.Cols,
		cmd:       cmd,
		pty:       ptmx,
		cmdDone:   make(chan struct{}),
	}
	go s.waitLoop()
	go s.readLoop()
	return s, nil
}

func defaultShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	for _, sh := range []string{"/bin/bash", "/bin/zsh", "/bin/sh"} {
		if _, err := os.Stat(sh); err == nil {
			return sh
		}
	}
	return "/bin/sh"
}

func (s *Session) Info() protocol.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := 0
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}
	return protocol.SessionInfo{
		ID:        s.ID,
		Owner:     s.Owner,
		User:      s.User,
		PID:       pid,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		State:     string(s.state),
		Rows:      s.rows,
		Cols:      s.cols,
	}
}

func (s *Session) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return 0
}

func (s *Session) Attach() (*Attachment, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == StateClosed {
		return nil, nil, fmt.Errorf("session %s is closed", s.ID)
	}
	if s.attach != nil {
		return nil, nil, fmt.Errorf("session %s already attached", s.ID)
	}
	a := &Attachment{
		s:      s,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	s.attach = a
	s.state = StateAttached
	snap := append([]byte(nil), s.ring...)
	return a, snap, nil
}

func (a *Attachment) Write(p []byte) (int, error) {
	if a.s.pty == nil {
		return 0, io.ErrClosedPipe
	}
	return a.s.pty.Write(p)
}

func (a *Attachment) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return fmt.Errorf("invalid size %dx%d", cols, rows)
	}
	a.s.mu.Lock()
	a.s.rows = rows
	a.s.cols = cols
	ptmx := a.s.pty
	a.s.mu.Unlock()
	return pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (a *Attachment) Signal(name string) error {
	return a.s.Signal(name)
}

func (a *Attachment) Recv() ([]byte, error) {
	select {
	case b := <-a.out:
		return b, nil
	case <-a.closed:
		select {
		case b := <-a.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	}
}

func (a *Attachment) RecvTimeout(d time.Duration) ([]byte, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b := <-a.out:
		return b, nil
	case <-a.closed:
		select {
		case b := <-a.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (a *Attachment) SessionClosed() bool {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	return a.s.closed || a.s.state == StateClosed
}

func (a *Attachment) ExitCode() int {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	return a.s.exitCode
}

func (a *Attachment) Detach() {
	a.s.mu.Lock()
	if a.s.attach == a {
		a.closeOut()
		a.s.attach = nil
		if a.s.state == StateAttached {
			a.s.state = StateDetached
		}
	}
	a.s.mu.Unlock()
}

func (a *Attachment) closeOut() {
	a.closeOnce.Do(func() {
		close(a.closed)
	})
}

func (s *Session) Signal(name string) error {
	s.mu.Lock()
	ptmx := s.pty
	proc := s.cmd.Process
	s.mu.Unlock()
	if ptmx == nil {
		return fmt.Errorf("session has no pty")
	}
	switch name {
	case "INT", "SIGINT", "2":
		_, err := ptmx.Write([]byte{0x03})
		return err
	case "TSTP", "SIGTSTP", "Z", "20":
		_, err := ptmx.Write([]byte{0x1a})
		return err
	case "QUIT", "SIGQUIT", "3":
		_, err := ptmx.Write([]byte{0x1c})
		return err
	case "TERM", "SIGTERM", "15":
		if proc == nil {
			return fmt.Errorf("session has no process")
		}
		return proc.Signal(syscall.SIGTERM)
	case "KILL", "SIGKILL", "9":
		if proc == nil {
			return fmt.Errorf("session has no process")
		}
		return proc.Kill()
	default:
		return fmt.Errorf("unsupported signal %q", name)
	}
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.state = StateClosed
		cmd := s.cmd
		ptmx := s.pty
		if s.attach != nil {
			s.attach.closeOut()
			s.attach = nil
		}
		s.mu.Unlock()

		if cmd != nil && cmd.Process != nil {
			pid := cmd.Process.Pid
			_ = syscall.Kill(-pid, syscall.SIGHUP)
			_ = syscall.Kill(pid, syscall.SIGHUP)
		}
		if ptmx != nil {
			_ = ptmx.Close()
		}
		select {
		case <-s.cmdDone:
		case <-time.After(500 * time.Millisecond):
			if cmd != nil && cmd.Process != nil {
				pid := cmd.Process.Pid
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				_ = cmd.Process.Kill()
			}
			select {
			case <-s.cmdDone:
			case <-time.After(500 * time.Millisecond):
			}
		}
	})
	return nil
}

func (s *Session) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			s.broadcast(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (s *Session) waitLoop() {
	err := s.cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	s.mu.Lock()
	s.exitCode = code
	s.closed = true
	s.state = StateClosed
	if s.attach != nil {
		s.attach.closeOut()
		s.attach = nil
	}
	s.mu.Unlock()
	close(s.cmdDone)
}

func (s *Session) broadcast(p []byte) {
	cp := append([]byte(nil), p...)
	s.mu.Lock()
	s.ring = append(s.ring, cp...)
	if len(s.ring) > ringMax {
		s.ring = append([]byte(nil), s.ring[len(s.ring)-ringMax:]...)
	}
	att := s.attach
	s.mu.Unlock()
	if att == nil {
		return
	}
	select {
	case <-att.closed:
	case att.out <- cp:
	}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func (s *Session) Alive() bool {
	return processAlive(s.PID())
}
