package session

import (
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"tyd/internal/live"
	"tyd/internal/protocol"
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
	if m.outputLogMax <= 0 {
		m.outputLogMax = live.DefaultOutputLogMax
	}
}

// SetOutputLogMax sets the per-session disk cap for new live-agents.
func (m *Manager) SetOutputLogMax(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= 0 {
		n = live.DefaultOutputLogMax
	}
	m.outputLogMax = n
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
		ID:         id,
		Owner:      owner,
		User:       owner,
		PeerID:     opts.PeerID,
		CreatedAt:  created,
		state:      StateDetached,
		idleSince:  created,
		rows:       opts.Rows,
		cols:       opts.Cols,
		cmdDone:    make(chan struct{}),
		liveDir:    dir,
		agentCmd:   cmd,
		ownerPub:   opts.OwnerPub,
		opts:       opts,
		agentSpawn: m.agentSpawner(id, owner, opts, created),
	}
	s.startLiveWaitLocked()
	return s, nil
}

func (m *Manager) spawnAgent(id, owner string, opts CreateOpts, created time.Time) (string, *exec.Cmd, error) {
	m.mu.Lock()
	root := m.liveRoot
	execPath := m.execPath
	starter := m.starter
	logMax := m.outputLogMax
	m.mu.Unlock()
	return spawnAgentWith(root, execPath, starter, id, owner, opts, created, logMax)
}

// agentSpawner snapshots the spawn parameters now and returns a callable that
// needs no manager lock. Sessions respawn their agent while holding s.mu, and
// m.mu is acquired before s.mu elsewhere, so taking m.mu here would invert the
// order.
func (m *Manager) agentSpawner(id, owner string, opts CreateOpts, created time.Time) func() (string, *exec.Cmd, error) {
	m.mu.Lock()
	root := m.liveRoot
	execPath := m.execPath
	starter := m.starter
	logMax := m.outputLogMax
	m.mu.Unlock()
	return func() (string, *exec.Cmd, error) {
		return spawnAgentWith(root, execPath, starter, id, owner, opts, created, logMax)
	}
}

func spawnAgentWith(root, execPath string, starter live.Starter, id, owner string, opts CreateOpts, created time.Time, logMax int64) (string, *exec.Cmd, error) {
	if starter == nil {
		starter = live.DefaultStarter
	}
	dir := live.Dir(root, id)
	meta := live.Meta{
		ID:           id,
		Owner:        owner,
		OwnerPub:     opts.OwnerPub,
		PeerID:       opts.PeerID,
		Shell:        opts.Shell,
		Cwd:          opts.Cwd,
		Rows:         opts.Rows,
		Cols:         opts.Cols,
		CreatedAt:    created.Format(time.RFC3339),
		OutputLogMax: logMax,
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
	s.opts = opts
	s.agentSpawn = m.agentSpawner(id, owner, opts, created)
	s.rows = opts.Rows
	s.cols = opts.Cols
	s.state = StateDetached
	s.idleSince = time.Now().UTC()
	s.cmdDone = make(chan struct{})
	s.startLiveWaitLocked()
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
		opts := CreateOpts{
			Rows:     meta.Rows,
			Cols:     meta.Cols,
			Shell:    meta.Shell,
			Cwd:      meta.Cwd,
			Owner:    meta.Owner,
			OwnerPub: meta.OwnerPub,
			PeerID:   meta.PeerID,
		}
		// A live agent with no shell pid outlived its shell: it is still a
		// session, and attaching to it starts a new shell.
		state := StateDetached
		if !live.ShellAlive(dir) {
			state = StateExited
		}
		s := &Session{
			ID:         meta.ID,
			Owner:      meta.Owner,
			User:       meta.Owner,
			PeerID:     meta.PeerID,
			CreatedAt:  created,
			state:      state,
			idleSince:  time.Now().UTC(),
			rows:       meta.Rows,
			cols:       meta.Cols,
			cmdDone:    make(chan struct{}),
			liveDir:    dir,
			ownerPub:   meta.OwnerPub,
			opts:       opts,
			agentSpawn: m.agentSpawner(meta.ID, meta.Owner, opts, created),
			onClosed:   onClosed,
		}
		m.mu.Lock()
		if _, exists := m.sessions[s.ID]; exists {
			m.mu.Unlock()
			continue
		}
		m.sessions[s.ID] = s
		m.mu.Unlock()
		s.startLiveWaitLocked()
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
			s.idleSince = time.Now().UTC()
		}
	}
	s.closeWatchersLocked()
}

// startLiveWaitLocked starts the agent watcher for the current generation. The
// caller must hold s.mu, or own the session before it is shared: the generation
// is captured here so that a later respawn cannot make an older loop wait on the
// new agent.
func (s *Session) startLiveWaitLocked() {
	go s.liveWaitLoop(s.agentCmd, s.liveDir, s.cmdDone)
}

// liveWaitLoop waits for the live agent process to go away. Like the in-process
// path, that leaves the session alive rather than closed: a new agent is
// started on the next attach. An explicit close still wins the race and must
// not be undone here.
func (s *Session) liveWaitLoop(agentCmd *exec.Cmd, dir string, cmdDone chan struct{}) {
	if agentCmd != nil {
		_ = agentCmd.Wait()
	} else {
		for live.Alive(dir) {
			time.Sleep(500 * time.Millisecond)
		}
	}
	s.mu.Lock()
	if s.cmdDone != cmdDone {
		// A newer agent generation owns the session now: this loop is stale and
		// must not touch the state the new generation already installed.
		s.mu.Unlock()
		return
	}
	if s.closed || s.state == StateClosed {
		s.mu.Unlock()
		markDone(cmdDone)
		return
	}
	s.agentCmd = nil
	s.state = StateExited
	// Idle reaping counts from the moment the agent went away.
	s.idleSince = time.Now().UTC()
	notice := exitNotice(s.exitCode)
	s.ringAppendLocked(notice)
	att := s.attach
	if att != nil {
		if att.live != nil {
			att.live.Close()
		}
		att.shellExited = true
		att.closeOut()
		s.attach = nil
	}
	watchers := append([]*Watcher(nil), s.watchers...)
	for _, w := range watchers {
		if w.live != nil {
			w.live.Close()
		}
		w.shellExited = true
	}
	s.closeWatchersLocked()
	s.mu.Unlock()

	deliver(att, watchers, notice)
	markDone(cmdDone)
}

// markDone closes a done channel at most once.
func markDone(done chan struct{}) {
	if done == nil {
		return
	}
	select {
	case <-done:
	default:
		close(done)
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
	s.mu.Lock()
	cmdDone := s.cmdDone
	s.mu.Unlock()
	select {
	case <-cmdDone:
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
	markDone(cmdDone)
	return nil
}

func (s *Session) attachLive() (*Attachment, []byte, error) {
	if s.state == StateExited {
		// The agent is gone but the session is alive: bring a new one up for
		// the same id. The fresh agent has no history, so the replay starts
		// empty; the previous shell's output went with the old agent.
		if err := s.respawnAgentLocked(); err != nil {
			return nil, nil, err
		}
	}
	var lc *live.Conn
	var snap []byte
	var info protocol.SessionInfo
	var err error
	for i := 0; i < 20; i++ {
		lc, snap, info, err = live.DialAttach(s.liveDir, s.rows, s.cols)
		if err == nil || !strings.Contains(err.Error(), "already attached") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
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
	s.idleSince = time.Time{}
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

// respawnAgentLocked starts a fresh live-agent for a session whose previous
// agent is gone. The session keeps its id, creation time, and recorded
// options; only the agent (and with it any output the agent still held) is
// new. The caller must hold s.mu.
func (s *Session) respawnAgentLocked() error {
	if s.agentSpawn == nil {
		return fmt.Errorf("session %s has no live agent to restart", s.ID)
	}
	dir, cmd, err := s.agentSpawn()
	if err != nil {
		return err
	}
	s.liveDir = dir
	s.agentCmd = cmd
	s.cmdDone = make(chan struct{})
	s.state = StateDetached
	s.startLiveWaitLocked()
	return nil
}

// refreshLiveLocked syncs the daemon's view with the live agent. An agent that
// outlived its shell leaves the session alive but shell-less; the agent records
// that by removing its shell pid file. The exit time does not survive in the
// agent, so the idle clock starts when the daemon first notices.
// The caller must hold s.mu.
func (s *Session) refreshLiveLocked() {
	if s.liveDir == "" || s.closed || s.state == StateClosed || s.state == StatePending {
		return
	}
	switch s.state {
	case StateExited:
		// An attach may have started a new shell in the agent.
		if live.ShellAlive(s.liveDir) {
			s.state = StateDetached
			s.idleSince = time.Now().UTC()
		}
	case StateDetached, StateAttached:
		if !live.ShellAlive(s.liveDir) {
			s.state = StateExited
			s.idleSince = time.Now().UTC()
		}
	}
}
