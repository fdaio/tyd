package session

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"tyd/internal/protocol"
)

type State string

const (
	StatePending  State = "PENDING"
	StateAttached State = "ATTACHED"
	StateDetached State = "DETACHED"
	StateClosed   State = "CLOSED"
)

const ringMax = 64 << 10

type CreateOpts struct {
	Rows   uint16
	Cols   uint16
	Shell  string
	Cwd    string
	Env    []string
	Owner  string
	PeerID string // optional; recorded for post-approval audit
}

// ClosedInfo is emitted when a live session transitions to CLOSED (not pending reject).
type ClosedInfo struct {
	SessionID string
	Principal string
	PeerID    string
	CreatedAt time.Time
	ClosedAt  time.Time
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	onClosed func(ClosedInfo)
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session)}
}

// SetOnClosed registers a callback for sessions that become CLOSED (shell exit or Close).
// Pending reject/remove does not fire the callback.
func (m *Manager) SetOnClosed(fn func(ClosedInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onClosed = fn
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
	s.onClosed = m.onClosed
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// CreatePending allocates a session in PENDING without starting a PTY.
func (m *Manager) CreatePending(opts CreateOpts) (*Session, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	normalizeCreateOpts(&opts)
	owner := opts.Owner
	if owner == "" {
		if u, err := user.Current(); err == nil {
			owner = u.Username
		}
	}
	s := &Session{
		ID:        id,
		Owner:     owner,
		User:      owner,
		PeerID:    opts.PeerID,
		CreatedAt: time.Now().UTC(),
		state:     StatePending,
		rows:      opts.Rows,
		cols:      opts.Cols,
		pending:   &opts,
		cmdDone:   make(chan struct{}),
	}
	m.mu.Lock()
	s.onClosed = m.onClosed
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Approve starts the PTY for a PENDING session and moves it to DETACHED.
func (m *Manager) Approve(id string) (*Session, error) {
	s, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if err := s.approve(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reject removes a PENDING session. Non-pending sessions return an error.
func (m *Manager) Reject(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session %s not found", id)
	}
	s.mu.Lock()
	pending := s.state == StatePending
	s.mu.Unlock()
	if !pending {
		m.mu.Unlock()
		return fmt.Errorf("session %s is not pending", id)
	}
	delete(m.sessions, id)
	m.mu.Unlock()
	return nil
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
	sort.SliceStable(out, func(i, j int) bool {
		iClosed := out[i].State == string(StateClosed)
		jClosed := out[j].State == string(StateClosed)
		if iClosed != jClosed {
			return !iClosed // alive (non-CLOSED, including PENDING) first
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out
}

func (m *Manager) Close(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session %s not found", id)
	}
	s.mu.Lock()
	pending := s.state == StatePending
	s.mu.Unlock()
	if pending {
		delete(m.sessions, id)
		m.mu.Unlock()
		return nil
	}
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
		s.mu.Lock()
		pending := s.state == StatePending
		s.mu.Unlock()
		if pending {
			continue
		}
		_ = s.Close()
	}
}

type Session struct {
	ID        string
	Owner     string
	User      string
	PeerID    string
	CreatedAt time.Time

	mu         sync.Mutex
	state      State
	rows       uint16
	cols       uint16
	cmd        *exec.Cmd
	pty        *os.File
	attach     *Attachment
	watchers   []*Watcher
	ring       []byte
	exitCode   int
	closed     bool
	closedAt   time.Time
	closeOnce  sync.Once
	closedOnce sync.Once
	cmdDone    chan struct{}
	pending    *CreateOpts
	onClosed   func(ClosedInfo)
}

type Attachment struct {
	s         *Session
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

type Watcher struct {
	s         *Session
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func normalizeCreateOpts(opts *CreateOpts) {
	if opts.Rows == 0 {
		opts.Rows = 24
	}
	if opts.Cols == 0 {
		opts.Cols = 80
	}
	if opts.Shell == "" {
		opts.Shell = defaultShell()
	}
}

func startSession(id string, opts CreateOpts) (*Session, error) {
	normalizeCreateOpts(&opts)
	cmd, ptmx, err := startPTY(opts)
	if err != nil {
		return nil, err
	}

	owner := opts.Owner
	if owner == "" {
		if u, err := user.Current(); err == nil {
			owner = u.Username
		}
	}

	s := &Session{
		ID:        id,
		Owner:     owner,
		User:      owner,
		PeerID:    opts.PeerID,
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

func startPTY(opts CreateOpts) (*exec.Cmd, *os.File, error) {
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
		return nil, nil, fmt.Errorf("start pty: %w", err)
	}
	return cmd, ptmx, nil
}

func (s *Session) approve() error {
	s.mu.Lock()
	if s.closed || s.state == StateClosed {
		s.mu.Unlock()
		return fmt.Errorf("session %s is closed", s.ID)
	}
	if s.state != StatePending || s.pending == nil {
		s.mu.Unlock()
		return fmt.Errorf("session %s is not pending", s.ID)
	}
	opts := *s.pending
	s.mu.Unlock()

	cmd, ptmx, err := startPTY(opts)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StatePending {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Errorf("session %s is not pending", s.ID)
	}
	s.pending = nil
	s.cmd = cmd
	s.pty = ptmx
	s.state = StateDetached
	s.cmdDone = make(chan struct{})
	go s.waitLoop()
	go s.readLoop()
	return nil
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

func (s *Session) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
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
	if s.state == StatePending {
		return nil, nil, fmt.Errorf("session pending approval")
	}
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

func (s *Session) Watch() (*Watcher, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StatePending {
		return nil, nil, fmt.Errorf("session pending approval")
	}
	snap := append([]byte(nil), s.ring...)
	w := &Watcher{
		s:      s,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	if s.closed || s.state == StateClosed {
		w.closeOnce.Do(func() { close(w.closed) })
		return w, snap, nil
	}
	s.watchers = append(s.watchers, w)
	return w, snap, nil
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

func (w *Watcher) Recv() ([]byte, error) {
	select {
	case b := <-w.out:
		return b, nil
	case <-w.closed:
		select {
		case b := <-w.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	}
}

func (w *Watcher) RecvTimeout(d time.Duration) ([]byte, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b := <-w.out:
		return b, nil
	case <-w.closed:
		select {
		case b := <-w.out:
			return b, nil
		default:
			return nil, io.EOF
		}
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (w *Watcher) SessionClosed() bool {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.closed || w.s.state == StateClosed
}

func (w *Watcher) ExitCode() int {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.exitCode
}

func (w *Watcher) Close() {
	w.s.mu.Lock()
	for i, x := range w.s.watchers {
		if x == w {
			w.s.watchers = append(w.s.watchers[:i], w.s.watchers[i+1:]...)
			break
		}
	}
	w.closeOut()
	w.s.mu.Unlock()
}

func (w *Watcher) closeOut() {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
}

func (s *Session) closeWatchersLocked() {
	for _, w := range s.watchers {
		w.closeOut()
	}
	s.watchers = nil
}

func (s *Session) Signal(name string) error {
	s.mu.Lock()
	if s.state == StatePending {
		s.mu.Unlock()
		return fmt.Errorf("session pending approval")
	}
	ptmx := s.pty
	var proc *os.Process
	if s.cmd != nil {
		proc = s.cmd.Process
	}
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

func (s *Session) fireClosedLocked() {
	s.closedOnce.Do(func() {
		if s.closedAt.IsZero() {
			s.closedAt = time.Now().UTC()
		}
		fn := s.onClosed
		info := ClosedInfo{
			SessionID: s.ID,
			Principal: s.Owner,
			PeerID:    s.PeerID,
			CreatedAt: s.CreatedAt,
			ClosedAt:  s.closedAt,
		}
		if fn == nil {
			return
		}
		go fn(info)
	})
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.state == StatePending {
		s.mu.Unlock()
		return fmt.Errorf("session pending approval; use reject")
	}
	if s.closed || s.state == StateClosed {
		s.mu.Unlock()
		return fmt.Errorf("already closed")
	}
	s.mu.Unlock()

	ran := false
	s.closeOnce.Do(func() {
		ran = true
		s.mu.Lock()
		if s.closed || s.state == StateClosed {
			s.mu.Unlock()
			ran = false
			return
		}
		s.closed = true
		s.state = StateClosed
		s.closedAt = time.Now().UTC()
		cmd := s.cmd
		ptmx := s.pty
		if s.attach != nil {
			s.attach.closeOut()
			s.attach = nil
		}
		s.closeWatchersLocked()
		s.fireClosedLocked()
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
	if !ran {
		return fmt.Errorf("already closed")
	}
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
	s.closedAt = time.Now().UTC()
	if s.attach != nil {
		s.attach.closeOut()
		s.attach = nil
	}
	s.closeWatchersLocked()
	s.fireClosedLocked()
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
	watchers := append([]*Watcher(nil), s.watchers...)
	s.mu.Unlock()
	if att != nil {
		select {
		case <-att.closed:
		case att.out <- cp:
		}
	}
	for _, w := range watchers {
		select {
		case <-w.closed:
		case w.out <- cp:
		}
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
