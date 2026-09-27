package live

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Starter starts a live-agent process for dir. Tests may override.
type Starter func(execPath, dir string) (*exec.Cmd, error)

// DefaultStarter launches `execPath __live-agent --dir <dir>` in a new session.
func DefaultStarter(execPath, dir string) (*exec.Cmd, error) {
	if execPath == "" {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	logf, err := os.OpenFile(LogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(execPath, "__live-agent", "--dir", dir)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		return nil, err
	}
	// Parent no longer needs the log fd; child keeps it.
	_ = logf.Close()
	return cmd, nil
}

// WaitSock blocks until the agent unix socket accepts connections or timeout.
func WaitSock(dir string, timeout time.Duration) error {
	sock := SockPath(dir)
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", sock, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err
		time.Sleep(25 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return fmt.Errorf("wait agent sock %s: %w", sock, last)
}

// Alive reports whether the agent pid file points at a live process and sock exists.
func Alive(dir string) bool {
	pid, err := ReadPID(AgentPIDPath(dir))
	if err != nil {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	if _, err := os.Stat(SockPath(dir)); err != nil {
		return false
	}
	return true
}

// KillAgent best-effort SIGTERM then SIGKILL on the agent process group.
func KillAgent(dir string) {
	pid, err := ReadPID(AgentPIDPath(dir))
	if err != nil {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	_ = syscall.Kill(pid, syscall.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// ShellAlive reports whether the session's shell process is recorded as
// running. An agent that outlived its shell removes the pid file, so a live
// agent without one means "session alive, no shell".
func ShellAlive(dir string) bool {
	pid, err := ReadPID(ShellPIDPath(dir))
	if err != nil {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
