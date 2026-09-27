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

	"tyd/internal/live"
	"tyd/internal/protocol"
)

type State string

const (
	StatePending  State = "PENDING"
	StateAttached State = "ATTACHED"
	StateDetached State = "DETACHED"
	StateClosed   State = "CLOSED"
	// StateExited marks a live session whose shell has exited. The session is
	// still alive and can be attached again, which starts a fresh shell.
	StateExited State = "EXITED"
)

const ringMax = 64 << 10

type CreateOpts struct {
	Rows     uint16
	Cols     uint16
	Shell    string
	Cwd      string
	Env      []string
	Owner    string
	OwnerPub string // base64 ed25519 public key; restored after daemon restart
	PeerID   string // optional; recorded for post-approval audit
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
	liveRoot string
	execPath string
	starter  live.Starter
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
	m.mu.Lock()
	useLive := m.liveRoot != ""
	m.mu.Unlock()
	var s *Session
	if useLive {
		s, err = m.startLiveSession(id, opts)
	} else {
		s, err = startSession(id, opts)
	}
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
	m.mu.Lock()
	useLive := m.liveRoot != ""
	m.mu.Unlock()
	if useLive {
		if err := s.approveLive(m); err != nil {
			return nil, err
		}
		return s, nil
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
		return out[i].CreatedAt > out[j].CreatedAt // newest first within group
	})
	return out
}

// IdleSince reports when the session became unattended. Zero means attached,
// pending, closed, or exited.
func (s *Session) IdleSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLiveLocked()
	if s.state != StateDetached && s.state != StateExited {
		return time.Time{}
	}
	return s.idleSince
}

// ReapIdle closes DETACHED and EXITED sessions unattended for longer than
// idle and returns their ids. PENDING sessions are left for the operator to
// decide.
func (m *Manager) ReapIdle(idle time.Duration, now time.Time) []string {
	if idle <= 0 {
		return nil
	}
	m.mu.Lock()
	candidates := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		candidates = append(candidates, s)
	}
	m.mu.Unlock()

	var closed []string
	for _, s := range candidates {
		since := s.IdleSince()
		if since.IsZero() || now.Sub(since) < idle {
			continue
		}
		if err := m.Close(s.ID); err == nil {
			closed = append(closed, s.ID)
		}
	}
	sort.Strings(closed)
	return closed
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
	idleSince  time.Time // when the session became unattended; zero while attached
	onClosed   func(ClosedInfo)
	liveDir    string
	agentCmd   *exec.Cmd
	ownerPub   string
	opts       CreateOpts // retained so an exited shell can be respawned on attach
	// agentSpawn starts a replacement live-agent for this session. Set for
	// live sessions only; nil means there is nothing to respawn.
	agentSpawn func() (string, *exec.Cmd, error)
}

type Attachment struct {
	s           *Session
	out         chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
	live        *live.Conn
	shellExited bool // stream ended because the shell exited, not the session
}

type Watcher struct {
	s           *Session
	out         chan []byte
	closed      chan struct{}
	closeOnce   sync.Once
	live        *live.Conn
	shellExited bool // stream ended because the shell exited, not the session
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

	created := time.Now().UTC()
	s := &Session{
		ID:        id,
		Owner:     owner,
		User:      owner,
		PeerID:    opts.PeerID,
		CreatedAt: created,
		state:     StateDetached,
		idleSince: created,
		rows:      opts.Rows,
		cols:      opts.Cols,
		cmd:       cmd,
		pty:       ptmx,
		cmdDone:   make(chan struct{}),
		opts:      opts,
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

	// Live mode is decided by the manager at CreatePending time via opts;
	// pending approve uses in-process PTY unless the session was marked live.
	// Manager.Approve always goes through startPTY unless liveRoot was set on create.
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
	s.idleSince = time.Now().UTC()
	s.cmdDone = make(chan struct{})
	s.opts = opts
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
	s.refreshLiveLocked()
	pid := 0
	if s.liveDir != "" {
		pid = shellPIDFile(s.liveDir)
	} else if s.cmd != nil && s.cmd.Process != nil {
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
	s.refreshLiveLocked()
	return s.state
}

func (s *Session) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.liveDir != "" {
		return shellPIDFile(s.liveDir)
	}
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
		// A finished stream (the shell exited, or the client vanished without
		// the server tearing the attachment down) must not block a new attach.
		if !s.attach.endedLocked() {
			return nil, nil, fmt.Errorf("session %s already attached", s.ID)
		}
		s.attach = nil
	}
	if s.liveDir != "" {
		return s.attachLive()
	}
	if s.state == StateExited {
		// The shell is gone but the session is alive: start a fresh one. The
		// ring is kept, so the replay below still shows the previous shell.
		if err := s.respawnLocked(); err != nil {
			return nil, nil, err
		}
	}
	a := &Attachment{
		s:      s,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
	}
	s.attach = a
	s.state = StateAttached
	s.idleSince = time.Time{}
	snap := append([]byte(nil), s.ring...)
	return a, snap, nil
}

// respawnLocked starts a fresh shell for a session whose previous shell
// exited. It reuses the create options recorded at approval time, with the
// session's last known window size; the caller re-applies the real size via
// Attachment.Resize once the new PTY exists. The caller must hold s.mu and must
// not have set s.attach yet.
func (s *Session) respawnLocked() error {
	opts := s.opts
	opts.Rows = s.rows
	opts.Cols = s.cols
	normalizeCreateOpts(&opts)
	cmd, ptmx, err := startPTY(opts)
	if err != nil {
		return err
	}
	s.cmd = cmd
	s.pty = ptmx
	s.cmdDone = make(chan struct{})
	s.exitCode = 0
	s.rows = opts.Rows
	s.cols = opts.Cols
	go s.waitLoop()
	go s.readLoop()
	return nil
}

func (s *Session) Watch() (*Watcher, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StatePending {
		return nil, nil, fmt.Errorf("session pending approval")
	}
	if s.liveDir != "" {
		return s.watchLive()
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
	if a.live != nil {
		return a.live.Write(p)
	}
	a.s.mu.Lock()
	ptmx := a.s.pty
	a.s.mu.Unlock()
	if ptmx == nil {
		return 0, io.ErrClosedPipe
	}
	return ptmx.Write(p)
}

func (a *Attachment) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return fmt.Errorf("invalid size %dx%d", cols, rows)
	}
	if a.live != nil {
		a.s.mu.Lock()
		a.s.rows = rows
		a.s.cols = cols
		a.s.mu.Unlock()
		return a.live.Resize(rows, cols)
	}
	a.s.mu.Lock()
	a.s.rows = rows
	a.s.cols = cols
	ptmx := a.s.pty
	a.s.mu.Unlock()
	return pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (a *Attachment) Signal(name string) error {
	if a.live != nil {
		return a.live.Signal(name)
	}
	return a.s.Signal(name)
}

func (a *Attachment) Recv() ([]byte, error) {
	if a.live != nil {
		return a.live.Recv()
	}
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
	if a.live != nil {
		return a.live.RecvTimeout(d)
	}
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
	if a.live != nil {
		return a.live.SessionClosed()
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	return a.s.closed || a.s.state == StateClosed
}

// ShellExited reports whether the stream ended because the session shell
// exited while the session itself is still alive and re-attachable.
func (a *Attachment) ShellExited() bool {
	if a.live != nil {
		return a.live.ShellExited()
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	return a.shellExited && !a.s.closed && a.s.state != StateClosed
}

func (a *Attachment) ExitCode() int {
	if a.live != nil {
		return a.live.ExitCode()
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	return a.s.exitCode
}

func (a *Attachment) Detach() {
	a.s.mu.Lock()
	if a.s.attach == a {
		if a.live != nil {
			a.live.Detach()
		}
		a.closeOut()
		a.s.attach = nil
		if a.s.state == StateAttached {
			a.s.state = StateDetached
			a.s.idleSince = time.Now().UTC()
		}
	}
	a.s.mu.Unlock()
}

// endedLocked reports whether this attachment's stream is already finished. The
// caller must hold a.s.mu.
func (a *Attachment) endedLocked() bool {
	if a.live != nil {
		return a.live.Ended()
	}
	select {
	case <-a.closed:
		return true
	default:
		return false
	}
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
	if w.live != nil {
		return w.live.SessionClosed()
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.closed || w.s.state == StateClosed
}

// ShellExited reports whether the stream ended because the session shell
// exited while the session itself is still alive and re-attachable.
func (w *Watcher) ShellExited() bool {
	if w.live != nil {
		return w.live.ShellExited()
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.shellExited && !w.s.closed && w.s.state != StateClosed
}

func (w *Watcher) ExitCode() int {
	if w.live != nil {
		return w.live.ExitCode()
	}
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
	if w.live != nil {
		w.live.Close()
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
	if s.liveDir != "" {
		if s.attach != nil && s.attach.live != nil {
			lc := s.attach.live
			s.mu.Unlock()
			return lc.Signal(name)
		}
		s.mu.Unlock()
		return fmt.Errorf("session not attached")
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
	liveDir := s.liveDir
	s.mu.Unlock()

	if liveDir != "" {
		return s.closeLive()
	}

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
	s.mu.Lock()
	ptmx := s.pty
	s.mu.Unlock()
	if ptmx == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			s.broadcast(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// waitLoop waits for the session shell to exit. Unlike a live session, a
// regular session survives its shell: the session only becomes StateExited, so
// it can be attached again (which respawns a fresh shell) and stays subject to
// idle reaping and explicit close. The session is deliberately not marked
// closed and no ClosedInfo fires here.
func (s *Session) waitLoop() {
	// Capture the process and its done channel: a later attach may respawn the
	// shell and replace both fields while this loop is still winding down.
	s.mu.Lock()
	cmd := s.cmd
	cmdDone := s.cmdDone
	s.mu.Unlock()
	err := cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	s.mu.Lock()
	if s.closed || s.state == StateClosed {
		// Close won the race with the exiting shell; do not resurrect the
		// session as EXITED. cmdDone is still ours to close.
		s.mu.Unlock()
		close(cmdDone)
		return
	}
	s.exitCode = code
	s.cmd = nil
	if s.pty != nil {
		_ = s.pty.Close()
		s.pty = nil
	}
	s.state = StateExited
	// Idle reaping counts from the moment the shell went away.
	s.idleSince = time.Now().UTC()
	// Tell whoever is attached or watching why the stream is ending, then end
	// it. The notice goes into the ring so a later attach replays it too.
	notice := exitNotice(code)
	s.ringAppendLocked(notice)
	att := s.attach
	s.attach = nil
	if att != nil {
		att.shellExited = true
	}
	watchers := append([]*Watcher(nil), s.watchers...)
	for _, w := range watchers {
		w.shellExited = true
	}
	s.mu.Unlock()

	// Deliver before closing so the notice is the last thing the client sees.
	deliver(att, watchers, notice)
	if att != nil {
		att.closeOut()
	}
	s.mu.Lock()
	s.closeWatchersLocked()
	s.mu.Unlock()
	close(cmdDone)
}

// exitNotice is the in-band message written to the ring when a session shell
// exits. It uses CRLF because it is read by terminals in raw mode.
func exitNotice(code int) []byte {
	return []byte(fmt.Sprintf("[tyd] shell exited (status %d) — session still attachable; attach again for a new shell\r\n", code))
}

func (s *Session) broadcast(p []byte) {
	cp := append([]byte(nil), p...)
	s.mu.Lock()
	s.ringAppendLocked(cp)
	att := s.attach
	watchers := append([]*Watcher(nil), s.watchers...)
	s.mu.Unlock()
	deliver(att, watchers, cp)
}

// ringAppendLocked adds p to the replay ring. The caller must hold s.mu.
func (s *Session) ringAppendLocked(p []byte) {
	s.ring = append(s.ring, p...)
	if len(s.ring) > ringMax {
		s.ring = append([]byte(nil), s.ring[len(s.ring)-ringMax:]...)
	}
}

// deliver fans p out to the given attachment and watchers. It is deliberately
// lock-free: the sends block until the consumer drains or the stream is closed.
func deliver(att *Attachment, watchers []*Watcher, p []byte) {
	if att != nil {
		select {
		case <-att.closed:
		case att.out <- p:
		}
	}
	for _, w := range watchers {
		select {
		case <-w.closed:
		case w.out <- p:
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
