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

	cmd := exec.Command(meta.Shell)
	if meta.Cwd != "" {
		cmd.Dir = meta.Cwd
	} else if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: meta.Rows, Cols: meta.Cols})
	if err != nil {
		return fmt.Errorf("start pty: %w", err)
	}

	if err := WritePID(AgentPIDPath(dir), os.Getpid()); err != nil {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return err
	}
	if cmd.Process != nil {
		_ = WritePID(ShellPIDPath(dir), cmd.Process.Pid)
	}

	sock := SockPath(dir)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = ptmx.Close()
		return err
	}

	a := &agent{
		dir:     dir,
		meta:    meta,
		cmd:     cmd,
		pty:     ptmx,
		ln:      ln,
		rows:    meta.Rows,
		cols:    meta.Cols,
		cmdDone: make(chan struct{}),
	}
	go a.waitLoop()
	go a.readLoop()
	err = a.serve()
	<-a.cmdDone
	return err
}

type agent struct {
	dir     string
	meta    Meta
	cmd     *exec.Cmd
	pty     *os.File
	ln      net.Listener
	cmdDone chan struct{}

	mu         sync.Mutex
	ring       []byte
	rows       uint16
	cols       uint16
	attach     net.Conn
	watchers   []net.Conn
	closed     bool
	exitCode   int
	closeOnce  sync.Once
	waitClosed sync.Once
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
	case protocol.TypeClose:
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClosed})
		a.killShell()
	default:
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: "expected attach, watch, or close"})
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
	a.attach = conn
	if f.Rows > 0 && f.Cols > 0 {
		a.rows = f.Rows
		a.cols = f.Cols
		_ = pty.Setsize(a.pty, &pty.Winsize{Rows: f.Rows, Cols: f.Cols})
	}
	info := a.infoLocked()
	snap := append([]byte(nil), a.ring...)
	a.mu.Unlock()

	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeAttached, Session: &info, Data: snap}); err != nil {
		a.clearAttach(conn)
		return
	}

	for {
		rf, err := protocol.ReadFrame(conn)
		if err != nil {
			a.clearAttach(conn)
			return
		}
		switch rf.Type {
		case protocol.TypeWrite:
			if _, err := a.pty.Write(rf.Data); err != nil {
				a.clearAttach(conn)
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
			a.clearAttach(conn)
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeDetached})
			return
		case protocol.TypeClose:
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeClosed})
			a.killShell()
			return
		default:
			_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeError, Error: fmt.Sprintf("unsupported %q", rf.Type)})
		}
	}
}

func (a *agent) handleWatch(conn net.Conn) {
	a.mu.Lock()
	if a.closed {
		info := a.infoLocked()
		snap := append([]byte(nil), a.ring...)
		code := a.exitCode
		a.mu.Unlock()
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeWatching, Session: &info, Data: snap})
		_ = protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeExit, ExitCode: code})
		return
	}
	a.watchers = append(a.watchers, conn)
	info := a.infoLocked()
	snap := append([]byte(nil), a.ring...)
	a.mu.Unlock()

	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeWatching, Session: &info, Data: snap}); err != nil {
		a.removeWatcher(conn)
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
			a.removeWatcher(conn)
			return
		}
	}
}

func (a *agent) clearAttach(conn net.Conn) {
	a.mu.Lock()
	if a.attach == conn {
		a.attach = nil
	}
	a.mu.Unlock()
}

func (a *agent) removeWatcher(conn net.Conn) {
	a.mu.Lock()
	for i, w := range a.watchers {
		if w == conn {
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
	if a.closed {
		state = "CLOSED"
	} else if a.attach != nil {
		state = "ATTACHED"
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

func (a *agent) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := a.pty.Read(buf)
		if n > 0 {
			a.broadcast(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (a *agent) waitLoop() {
	err := a.cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	a.finish(code)
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
	att := a.attach
	watchers := append([]net.Conn(nil), a.watchers...)
	a.mu.Unlock()

	frame := protocol.Frame{Type: protocol.TypeOutput, Data: cp}
	if att != nil {
		if err := protocol.WriteFrame(att, frame); err != nil {
			a.clearAttach(att)
		}
	}
	for _, w := range watchers {
		if err := protocol.WriteFrame(w, frame); err != nil {
			a.removeWatcher(w)
			_ = w.Close()
		}
	}
}

func (a *agent) killShell() {
	a.mu.Lock()
	cmd := a.cmd
	ptmx := a.pty
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		pid := cmd.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGHUP)
		_ = syscall.Kill(pid, syscall.SIGHUP)
	}
	if ptmx != nil {
		_ = ptmx.Close()
	}
	select {
	case <-a.cmdDone:
	case <-time.After(500 * time.Millisecond):
		if cmd != nil && cmd.Process != nil {
			pid := cmd.Process.Pid
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		select {
		case <-a.cmdDone:
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
		watchers := append([]net.Conn(nil), a.watchers...)
		a.attach = nil
		a.watchers = nil
		ln := a.ln
		ptmx := a.pty
		a.mu.Unlock()

		exit := protocol.Frame{Type: protocol.TypeExit, ExitCode: exitCode}
		if att != nil {
			_ = protocol.WriteFrame(att, exit)
			_ = att.Close()
		}
		for _, w := range watchers {
			_ = protocol.WriteFrame(w, exit)
			_ = w.Close()
		}
		if ptmx != nil {
			_ = ptmx.Close()
		}
		if ln != nil {
			_ = ln.Close()
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
