package live

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"tyd/internal/protocol"
)

const ringMax = 64 << 10

// Run starts a live-agent in dir (blocking). Expects meta.json already written.
func Run(dir string) error {
	meta, err := LoadMeta(dir)
	if err != nil {
		return err
	}
	if meta.Rows == 0 {
		meta.Rows = 24
	}
	if meta.Cols == 0 {
		meta.Cols = 80
	}
	if meta.Shell == "" {
		meta.Shell = defaultShell()
	}

	if err := WritePID(AgentPIDPath(dir), os.Getpid()); err != nil {
		return err
	}

	a := &agent{
		dir:     dir,
		meta:    meta,
		rows:    meta.Rows,
		cols:    meta.Cols,
		cmdDone: make(chan struct{}),
		outLog:  openOutputLog(dir, meta.OutputLogMax),
	}
	// Start the shell before listening: a daemon that sees the socket can then
	// rely on the shell pid file being present, which is how it tells a
	// running shell from an exited one.
	if err := a.startShell(); err != nil {
		a.outLog.Close()
		return err
	}

	sock := SockPath(dir)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		a.killShell()
		a.finish(1)
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		a.killShell()
		a.finish(1)
		return err
	}
	a.ln = ln
	// serve returns only when the listener closes, which happens on an
	// explicit close. A shell that exits does not end the agent: the session
	// stays alive and re-attachable, and the ring is kept for replay.
	return a.serve()
}

// startShell starts a PTY for the recorded session. It locks internally.
func (a *agent) startShell() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startShellLocked()
}

// startShellLocked starts a PTY for the recorded session, reusing the current
// window size. The ring is deliberately not cleared: a respawned shell
// replays whatever the previous one printed. The caller must hold a.mu.
func (a *agent) startShellLocked() error {
	cmd := exec.Command(a.meta.Shell)
	if a.meta.Cwd != "" {
		cmd.Dir = a.meta.Cwd
	} else if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: a.rows, Cols: a.cols})
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}
	a.cmd = cmd
	a.pty = ptmx
	a.shellExited = false
	a.exitCode = 0
	a.shellDone = make(chan struct{})
	done := a.shellDone
	if cmd.Process != nil {
		_ = WritePID(ShellPIDPath(a.dir), cmd.Process.Pid)
	}
	go a.waitShell(cmd, done)
	go a.readShell(ptmx)
	return nil
}

// frameWriter serializes frames to one client connection. Two goroutines can
// want the same connection at once: the one answering the handshake and the one
// streaming shell output. Without a single writer the reply can land after a
// data frame, and two WriteFrame calls can interleave their bytes.
type frameWriter struct {
	mu    sync.Mutex
	conn  net.Conn
	ready bool // the handshake reply has been written
	queue []protocol.Frame
}

const frameQueueMax = 64

// reply writes the handshake reply and then flushes anything the stream wanted
// to send in the meantime, so the reply always arrives first and nothing that
// was produced during the handshake is dropped.
func (w *frameWriter) reply(f protocol.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := protocol.WriteFrame(w.conn, f); err != nil {
		return err
	}
	w.ready = true
	for _, q := range w.queue {
		if err := protocol.WriteFrame(w.conn, q); err != nil {
			w.queue = nil
			return err
		}
	}
	w.queue = nil
	return nil
}

// send writes a stream frame, holding it back until the reply has been sent.
func (w *frameWriter) send(f protocol.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.ready {
		if len(w.queue) < frameQueueMax {
			w.queue = append(w.queue, f)
		}
		return nil
	}
	return protocol.WriteFrame(w.conn, f)
}

// peer is one attached or watching client.
type peer struct {
	conn net.Conn
	w    *frameWriter
}

func newPeer(conn net.Conn) *peer {
	return &peer{conn: conn, w: &frameWriter{conn: conn}}
}

type agent struct {
	dir     string
	meta    Meta
	cmd     *exec.Cmd
	pty     *os.File
	ln      net.Listener
	cmdDone chan struct{}

	mu sync.Mutex
	// ioMu serialises a send's PTY write against an attach taking the slot.
	// It is separate from mu because the write can block, and mu is needed
	// by the shell reader that would unblock it.
	ioMu        sync.Mutex
	ring        []byte
	rows        uint16
	cols        uint16
	attach      *peer
	watchers    []*peer
	closed      bool // the session is closed: tear everything down
	closing     bool // a close was requested; the next shell exit finishes
	shellExited bool // the shell is gone but the session is alive
	exitCode    int
	shellDone   chan struct{} // closed when the current shell exits
	closeOnce   sync.Once
	waitClosed  sync.Once
	waiters     int // reads parked in ReadAtWait
	outLog      *outputLog
}

func (a *agent) serve() error {
	defer func() {
		_ = a.ln.Close()
		_ = os.Remove(SockPath(a.dir))
	}()
	for {
		conn, err := a.ln.Accept()
		if err != nil {
			a.mu.Lock()
			done := a.closed
			a.mu.Unlock()
			if done {
				return nil
			}
			return err
		}
		go a.handle(conn)
	}
}

func (a *agent) handle(conn net.Conn) {
	defer conn.Close()
	f, err := protocol.ReadFrame(conn)
	if err != nil {
		return
	}
	switch f.Type {
	case protocol.TypeAttach:
		a.handleAttach(conn, f)
	case protocol.TypeWatch:
		a.handleWatch(conn)
	case protocol.TypeRead:
		a.handleRead(conn, f)
	case protocol.TypeSend:
		a.handleSend(conn, f)
	case protocol.TypeClose:
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClosed})
		a.closeSession()
	default:
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "expected attach, watch, read, or close"})
	}
}

func (a *agent) handleAttach(conn net.Conn, f protocol.Frame) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "session closed"})
		return
	}
	if a.attach != nil {
		a.mu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "session already attached"})
		return
	}
	if f.Rows > 0 && f.Cols > 0 {
		a.rows = f.Rows
		a.cols = f.Cols
	}
	if a.shellExited {
		// The shell is gone but the session is alive: start a fresh one. The
		// ring is kept, so the reply below still replays the old output.
		if err := a.startShellLocked(); err != nil {
			a.mu.Unlock()
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
			return
		}
	}
	p := newPeer(conn)
	// Claim the slot under ioMu so a send in flight is not interleaved with
	// the attach that is about to own the session.
	a.ioMu.Lock()
	a.attach = p
	a.ioMu.Unlock()
	if a.pty != nil {
		_ = pty.Setsize(a.pty, &pty.Winsize{Rows: a.rows, Cols: a.cols})
	}
	info := a.infoLocked()
	snap := append([]byte(nil), a.ring...)
	a.mu.Unlock()

	if err := p.w.reply(protocol.Frame{Type: protocol.TypeAttached, Session: &info, Data: snap}); err != nil {
		a.clearAttach(p)
		return
	}

	for {
		rf, err := protocol.ReadFrame(conn)
		if err != nil {
			a.clearAttach(p)
			return
		}
		switch rf.Type {
		case protocol.TypeWrite:
			if _, err := a.pty.Write(rf.Data); err != nil {
				a.clearAttach(p)
				return
			}
		case protocol.TypeResize:
			if rf.Rows == 0 || rf.Cols == 0 {
				continue
			}
			a.mu.Lock()
			a.rows = rf.Rows
			a.cols = rf.Cols
			ptmx := a.pty
			a.mu.Unlock()
			_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rf.Rows, Cols: rf.Cols})
		case protocol.TypeSignal:
			_ = a.signal(rf.Signal)
		case protocol.TypeDetach:
			a.clearAttach(p)
			_ = p.w.send(protocol.Frame{Type: protocol.TypeDetached})
			return
		case protocol.TypeClose:
			_ = p.w.send(protocol.Frame{Type: protocol.TypeClosed})
			a.killShell()
			return
		default:
			_ = p.w.send(protocol.Frame{Type: protocol.TypeError, Error: fmt.Sprintf("unsupported %q", rf.Type)})
		}
	}
}

func (a *agent) handleRead(conn net.Conn, f protocol.Frame) {
	if !a.acquireWaiter() {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "too many reads waiting on this session"})
		return
	}
	defer a.releaseWaiter()
	a.mu.Lock()
	log := a.outLog
	closed := a.closed
	a.mu.Unlock()
	if closed {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "session closed"})
		return
	}
	// A condition with no wait would return at once, which is the opposite of
	// what the caller asked for.
	cond, err := ValidateConditions(f.IdleMS, f.Match, f.MaxBytes)
	if err != nil {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
		return
	}
	if cond.Any() && f.WaitMS == 0 {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "a read condition needs wait_ms"})
		return
	}
	var res ReadResult
	if log != nil {
		res = log.ReadAtWait(f.Cursor, f.Epoch, time.Duration(f.WaitMS)*time.Millisecond, cond, a.shellIsGone)
	} else {
		res = ReadResult{CursorNext: f.Cursor, AtEnd: true}
	}
	_ = protocol.WriteFrame(conn, protocol.Frame{
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
}

// maxReadWaiters bounds the reads parked on one session. Each holds a
// connection and a goroutine, so an unbounded count would let one peer pin
// the agent.
const maxReadWaiters = 16

func (a *agent) acquireWaiter() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.waiters >= maxReadWaiters {
		return false
	}
	a.waiters++
	return true
}

func (a *agent) releaseWaiter() {
	a.mu.Lock()
	if a.waiters > 0 {
		a.waiters--
	}
	a.mu.Unlock()
}

func (a *agent) shellIsGone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed || a.shellExited
}

// handleSend injects keystrokes without taking the attach slot. The occupancy
// check and the PTY write happen under ioMu, so an attach that starts in
// between cannot have its input interleaved with this write.
//
// The write must not hold a.mu. A PTY write blocks once the shell stops
// draining its input, and the echo that would drain it comes back through
// broadcast, which needs a.mu. Holding a.mu here would wedge the agent on any
// large send: the writer waits for a reader that is itself waiting.
func (a *agent) handleSend(conn net.Conn, f protocol.Frame) {
	a.ioMu.Lock()
	a.mu.Lock()
	switch {
	case a.closed:
		a.mu.Unlock()
		a.ioMu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "session closed"})
		return
	case a.attach != nil:
		// Do not name the holder: that would leak who is watching.
		a.mu.Unlock()
		a.ioMu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "session in use: attached elsewhere"})
		return
	case a.shellExited:
		// send never starts a shell. Respawning here would run a command the
		// caller never asked to run.
		a.mu.Unlock()
		a.ioMu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "shell exited; attach to start a new one"})
		return
	case a.pty == nil:
		a.mu.Unlock()
		a.ioMu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "no shell running"})
		return
	}
	// The cursor is the output end before this write, so a caller can send
	// and then read only what came after its own keystrokes. Without it a
	// read would race the echo and may pick up a prompt from earlier.
	cursor, epoch := a.outCursor()
	ptmx := a.pty
	a.mu.Unlock()
	// The PTY write happens with a.mu released: it blocks once the shell
	// stops draining its input, and the echo that would unblock it is
	// recorded through a.mu. Holding it here wedges the agent on a large send.
	n, err := ptmx.Write(f.Data)
	a.ioMu.Unlock()
	if err != nil {
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: err.Error()})
		return
	}
	_ = protocol.WriteFrame(conn, protocol.Frame{
		Type:       protocol.TypeOK,
		CursorNext: uint64(n),
		Cursor:     cursor,
		Epoch:      epoch,
	})
}

// outCursor is the log position and generation, for a send reply.
func (a *agent) outCursor() (uint64, uint64) {
	if a.outLog == nil {
		return 0, 0
	}
	return a.outLog.NextSeq(), a.outLog.Epoch()
}

func (a *agent) handleWatch(conn net.Conn) {
	a.mu.Lock()
	if a.closed || a.shellExited {
		info := a.infoLocked()
		snap := append([]byte(nil), a.ring...)
		code := a.exitCode
		a.mu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeWatching, Session: &info, Data: snap})
		if a.closed {
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeExit, ExitCode: code})
		} else {
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeExited, ExitCode: code})
		}
		return
	}
	p := newPeer(conn)
	a.watchers = append(a.watchers, p)
	info := a.infoLocked()
	snap := append([]byte(nil), a.ring...)
	a.mu.Unlock()

	if err := p.w.reply(protocol.Frame{Type: protocol.TypeWatching, Session: &info, Data: snap}); err != nil {
		a.removeWatcher(p)
		return
	}
	buf := make([]byte, 1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				a.mu.Lock()
				done := a.closed
				a.mu.Unlock()
				if done {
					return
				}
				continue
			}
			a.removeWatcher(p)
			return
		}
	}
}

func (a *agent) clearAttach(p *peer) {
	a.mu.Lock()
	if a.attach == p {
		a.attach = nil
	}
	a.mu.Unlock()
}

func (a *agent) removeWatcher(p *peer) {
	a.mu.Lock()
	for i, w := range a.watchers {
		if w == p {
			a.watchers = append(a.watchers[:i], a.watchers[i+1:]...)
			break
		}
	}
	a.mu.Unlock()
}

func (a *agent) infoLocked() protocol.SessionInfo {
	pid := 0
	if a.cmd != nil && a.cmd.Process != nil {
		pid = a.cmd.Process.Pid
	}
	state := "DETACHED"
	switch {
	case a.closed:
		state = "CLOSED"
	case a.attach != nil:
		state = "ATTACHED"
	case a.shellExited:
		state = "EXITED"
	}
	return protocol.SessionInfo{
		ID:        a.meta.ID,
		Owner:     a.meta.Owner,
		User:      a.meta.Owner,
		PID:       pid,
		CreatedAt: a.meta.CreatedAt,
		State:     state,
		Rows:      a.rows,
		Cols:      a.cols,
	}
}

func (a *agent) readShell(ptmx *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			a.broadcast(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// waitShell waits for one shell generation. Its exit does not end the session:
// unless a close was requested, the agent lingers so the session can be
// attached again.
func (a *agent) waitShell(cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	close(done)
	a.shellExit(code)
}

// shellExit records that the shell went away. The session survives: it becomes
// a shell-exited session that can be attached again, and idle reaping still
// applies. Attached clients and watchers are told the stream ended because the
// shell exited, not because the session closed.
func (a *agent) shellExit(code int) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	if a.closing {
		a.mu.Unlock()
		a.finish(code)
		return
	}
	a.shellExited = true
	a.exitCode = code
	notice := exitNotice(code)
	a.ring = append(a.ring, notice...)
	if len(a.ring) > ringMax {
		a.ring = append([]byte(nil), a.ring[len(a.ring)-ringMax:]...)
	}
	if a.outLog != nil {
		a.outLog.Append(notice)
	}
	att := a.attach
	a.attach = nil
	watchers := a.watchers
	a.watchers = nil
	ptmx := a.pty
	a.cmd = nil
	a.pty = nil
	a.mu.Unlock()

	// No shell pid means "this session has no shell", which is how a restarted
	// daemon tells an exited session from a running one.
	_ = os.Remove(ShellPIDPath(a.dir))
	if ptmx != nil {
		_ = ptmx.Close()
	}
	end := func(p *peer) {
		if p == nil {
			return
		}
		_ = p.w.send(protocol.Frame{Type: protocol.TypeOutput, Data: notice})
		_ = p.w.send(protocol.Frame{Type: protocol.TypeExited, ExitCode: code})
		_ = p.conn.Close()
	}
	end(att)
	for _, w := range watchers {
		end(w)
	}
}

// exitNotice is the in-band message written to the ring when the shell exits.
// It uses CRLF because it is read by terminals in raw mode.
func exitNotice(code int) []byte {
	return []byte(fmt.Sprintf("[tyd] shell exited (status %d) — session still attachable; attach again for a new shell\r\n", code))
}

func (a *agent) broadcast(p []byte) {
	cp := append([]byte(nil), p...)
	a.mu.Lock()
	if len(a.ring)+len(cp) > ringMax {
		need := len(a.ring) + len(cp) - ringMax
		if need >= len(a.ring) {
			a.ring = nil
		} else {
			a.ring = a.ring[need:]
		}
	}
	a.ring = append(a.ring, cp...)
	if a.outLog != nil {
		a.outLog.Append(cp)
	}
	att := a.attach
	watchers := append([]*peer(nil), a.watchers...)
	a.mu.Unlock()

	frame := protocol.Frame{Type: protocol.TypeOutput, Data: cp}
	if att != nil {
		if err := att.w.send(frame); err != nil {
			a.clearAttach(att)
		}
	}
	for _, w := range watchers {
		if err := w.w.send(frame); err != nil {
			a.removeWatcher(w)
			_ = w.conn.Close()
		}
	}
}

// closeSession ends the session for good: the shell is killed and the agent
// tears itself down, removing its dir.
func (a *agent) closeSession() {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	a.killShell()
	a.finish(0)
}

func (a *agent) killShell() {
	a.mu.Lock()
	cmd := a.cmd
	ptmx := a.pty
	done := a.shellDone
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		pid := cmd.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGHUP)
		_ = syscall.Kill(pid, syscall.SIGHUP)
	}
	if ptmx != nil {
		_ = ptmx.Close()
	}
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		if cmd != nil && cmd.Process != nil {
			pid := cmd.Process.Pid
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (a *agent) finish(exitCode int) {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.exitCode = exitCode
		att := a.attach
		watchers := append([]*peer(nil), a.watchers...)
		a.attach = nil
		a.watchers = nil
		ln := a.ln
		ptmx := a.pty
		a.mu.Unlock()

		exit := protocol.Frame{Type: protocol.TypeExit, ExitCode: exitCode}
		if att != nil {
			_ = att.w.send(exit)
			_ = att.conn.Close()
		}
		for _, w := range watchers {
			_ = w.w.send(exit)
			_ = w.conn.Close()
		}
		if ptmx != nil {
			_ = ptmx.Close()
		}
		if ln != nil {
			_ = ln.Close()
		}
		if a.outLog != nil {
			a.outLog.Close()
		}
		RemoveDir(a.dir)
		a.waitClosed.Do(func() { close(a.cmdDone) })
	})
}

func (a *agent) signal(name string) error {
	a.mu.Lock()
	ptmx := a.pty
	var proc *os.Process
	if a.cmd != nil {
		proc = a.cmd.Process
	}
	a.mu.Unlock()
	if ptmx == nil {
		return fmt.Errorf("no pty")
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
			return fmt.Errorf("no process")
		}
		return proc.Signal(syscall.SIGTERM)
	case "KILL", "SIGKILL", "9":
		if proc == nil {
			return fmt.Errorf("no process")
		}
		return proc.Kill()
	default:
		return fmt.Errorf("unsupported signal %q", name)
	}
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
