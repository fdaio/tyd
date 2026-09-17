package session

import (
	"fmt"
	"os/exec"
	"os/user"
	"time"

	"tyd/internal/live"
)

// RestoredLive is a session reattached from a still-running live-agent.
type RestoredLive struct {
	Session  *Session
	OwnerPub string
}

// ConfigureLive enables out-of-process PTY agents under root.
// When root is empty, Create keeps in-process PTYs (tests / legacy).
func (m *Manager) ConfigureLive(root, execPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.liveRoot = root
	m.execPath = execPath
	if m.starter == nil {
		m.starter = live.DefaultStarter
	}
}

// SetStarter overrides how live-agents are spawned (tests).
func (m *Manager) SetStarter(s live.Starter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starter = s
}

func (m *Manager) startLiveSession(id string, opts CreateOpts) (*Session, error) {
	normalizeCreateOpts(&opts)
	owner := opts.Owner
	if owner == "" {
		if u, err := user.Current(); err == nil {
			owner = u.Username
		}
	}
	created := time.Now().UTC()
	dir, cmd, err := m.spawnAgent(id, owner, opts, created)
	if err != nil {
		return nil, err
	}
	s := &Session{
		ID:        id,
		Owner:     owner,
		User:      owner,
		PeerID:    opts.PeerID,
		CreatedAt: created,
		state:     StateDetached,
		rows:      opts.Rows,
		cols:      opts.Cols,
		cmdDone:   make(chan struct{}),
		liveDir:   dir,
		agentCmd:  cmd,
		ownerPub:  opts.OwnerPub,
	}
	go s.liveWaitLoop()
	return s, nil
}

func (m *Manager) spawnAgent(id, owner string, opts CreateOpts, created time.Time) (string, *exec.Cmd, error) {
	m.mu.Lock()
	root := m.liveRoot
	execPath := m.execPath
	starter := m.starter
	m.mu.Unlock()
	if starter == nil {
		starter = live.DefaultStarter
	}
	dir := live.Dir(root, id)
	meta := live.Meta{
		ID:        id,
		Owner:     owner,
		OwnerPub:  opts.OwnerPub,
		PeerID:    opts.PeerID,
		Shell:     opts.Shell,
		Cwd:       opts.Cwd,
		Rows:      opts.Rows,
		Cols:      opts.Cols,
		CreatedAt: created.Format(time.RFC3339),
	}
	if err := live.SaveMeta(dir, meta); err != nil {
		return "", nil, err
	}
	cmd, err := starter(execPath, dir)
	if err != nil {
		live.RemoveDir(dir)
		return "", nil, fmt.Errorf("start live-agent: %w", err)
	}
	if err := live.WaitSock(dir, 5*time.Second); err != nil {
		live.KillAgent(dir)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		live.RemoveDir(dir)
		return "", nil, err
	}
	return dir, cmd, nil
}

func (s *Session) approveLive(m *Manager) error {
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
	id := s.ID
	owner := s.Owner
	created := s.CreatedAt
	s.mu.Unlock()

	normalizeCreateOpts(&opts)
	dir, cmd, err := m.spawnAgent(id, owner, opts, created)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StatePending {
		_ = live.RequestClose(dir)
		return fmt.Errorf("session %s is not pending", s.ID)
	}
	s.pending = nil
	s.liveDir = dir
	s.agentCmd = cmd
	s.ownerPub = opts.OwnerPub
	s.rows = opts.Rows
	s.cols = opts.Cols
	s.state = StateDetached
	s.cmdDone = make(chan struct{})
	go s.liveWaitLoop()
	return nil
}

// RestoreLive reclaims still-running agents under the configured live root.
// Dead agent dirs are removed. Caller should re-grant owner caps from OwnerPub.
func (m *Manager) RestoreLive() ([]RestoredLive, error) {
	m.mu.Lock()
	root := m.liveRoot
	onClosed := m.onClosed
	m.mu.Unlock()
	if root == "" {
		return nil, nil
	}
	dirs, err := live.ListDirs(root)
	if err != nil {
		return nil, err
	}
	var out []RestoredLive
	for _, dir := range dirs {
		meta, err := live.LoadMeta(dir)
		if err != nil {
			live.RemoveDir(dir)
			continue
		}
		if !live.Alive(dir) {
			live.RemoveDir(dir)
			continue
		}
		created := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, meta.CreatedAt); err == nil {
			created = t
		}
		s := &Session{
			ID:        meta.ID,
			Owner:     meta.Owner,
			User:      meta.Owner,
			PeerID:    meta.PeerID,
			CreatedAt: created,
			state:     StateDetached,
			rows:      meta.Rows,
			cols:      meta.Cols,
			cmdDone:   make(chan struct{}),
			liveDir:   dir,
			ownerPub:  meta.OwnerPub,
			onClosed:  onClosed,
		}
		m.mu.Lock()
		if _, exists := m.sessions[s.ID]; exists {
			m.mu.Unlock()
			continue
		}
		m.sessions[s.ID] = s
		m.mu.Unlock()
		go s.liveWaitLoop()
		out = append(out, RestoredLive{Session: s, OwnerPub: meta.OwnerPub})
	}
	return out, nil
}

// ReleaseAll detaches clients but leaves live-agents running (graceful daemon stop).
func (m *Manager) ReleaseAll() {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for id, s := range m.sessions {
		all = append(all, s)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, s := range all {
		s.release()
	}
}

// Shutdown stops the manager for daemon exit: live agents keep running; in-process PTYs are closed.
func (m *Manager) Shutdown() {
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
		isLive := s.liveDir != ""
		s.mu.Unlock()
		if pending {
			continue
		}
		if isLive {
			s.release()
			continue
		}
		_ = s.Close()
	}
}

func (s *Session) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attach != nil {
		if s.attach.live != nil {
			s.attach.live.Detach()
		} else {
			s.attach.closeOut()
		}
		s.attach = nil
		if s.state == StateAttached {
			s.state = StateDetached
		}
	}
	s.closeWatchersLocked()
}

func (s *Session) liveWaitLoop() {
	if s.agentCmd != nil {
		_ = s.agentCmd.Wait()
	} else {
		for live.Alive(s.liveDir) {
			time.Sleep(500 * time.Millisecond)
		}
	}
	s.mu.Lock()
	if s.closed || s.state == StateClosed {
		s.mu.Unlock()
		s.markCmdDone()
		return
	}
	s.closed = true
	s.state = StateClosed
	s.closedAt = time.Now().UTC()
	if s.attach != nil {
		if s.attach.live != nil {
			s.attach.live.Close()
		}
		s.attach.closeOut()
		s.attach = nil
	}
	s.closeWatchersLocked()
	s.fireClosedLocked()
	s.mu.Unlock()
	s.markCmdDone()
}

func (s *Session) markCmdDone() {
	select {
	case <-s.cmdDone:
	default:
		close(s.cmdDone)
	}
}

func (s *Session) closeLive() error {
	dir := s.liveDir
	if dir == "" {
		return fmt.Errorf("not a live session")
	}
	s.mu.Lock()
	if s.closed || s.state == StateClosed {
		s.mu.Unlock()
		return fmt.Errorf("already closed")
	}
	s.mu.Unlock()
	_ = live.RequestClose(dir)
	select {
	case <-s.cmdDone:
	case <-time.After(3 * time.Second):
		live.KillAgent(dir)
		live.RemoveDir(dir)
	}
	s.mu.Lock()
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
	s.markCmdDone()
	return nil
}

func (s *Session) attachLive() (*Attachment, []byte, error) {
	lc, snap, info, err := live.DialAttach(s.liveDir, s.rows, s.cols)
	if err != nil {
		return nil, nil, err
	}
	if info.Rows > 0 {
		s.rows = info.Rows
	}
	if info.Cols > 0 {
		s.cols = info.Cols
	}
	a := &Attachment{
		s:      s,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
		live:   lc,
	}
	s.attach = a
	s.state = StateAttached
	return a, snap, nil
}

func (s *Session) watchLive() (*Watcher, []byte, error) {
	lc, snap, _, err := live.DialWatch(s.liveDir)
	if err != nil {
		return nil, nil, err
	}
	w := &Watcher{
		s:      s,
		out:    make(chan []byte, 256),
		closed: make(chan struct{}),
		live:   lc,
	}
	if s.closed || s.state == StateClosed {
		w.closeOnce.Do(func() { close(w.closed) })
		lc.Close()
		return w, snap, nil
	}
	s.watchers = append(s.watchers, w)
	go w.pumpLive()
	return w, snap, nil
}

func (w *Watcher) pumpLive() {
	defer w.Close()
	for {
		b, err := w.live.Recv()
		if err != nil {
			return
		}
		select {
		case w.out <- b:
		case <-w.closed:
			return
		}
	}
}

func shellPIDFile(dir string) int {
	pid, err := live.ReadPID(live.ShellPIDPath(dir))
	if err != nil {
		return 0
	}
	return pid
}
