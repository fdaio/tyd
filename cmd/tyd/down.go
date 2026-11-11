package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tyd/internal/paths"
)

const (
	daemonStopWait = 2 * time.Second
	daemonPoll     = 50 * time.Millisecond
)

// runDown stops the local daemon. Sessions run in their own live agents, so
// they keep running; the next `tyd up` adopts them again.
func runDown(opts options) error {
	if err := refuseIfInSession("down"); err != nil {
		return err
	}
	res, err := stopDaemon(opts)
	if err != nil {
		return err
	}
	if !res.stopped {
		fmt.Println("tyd: daemon is not running")
		return nil
	}
	fmt.Println("daemon stopped")
	for _, hint := range res.hints {
		fmt.Println(hint)
	}
	return nil
}

type stopResult struct {
	stopped bool
	hints   []string
}

// stopDaemon stops the daemon that owns opts.socket. A service install is
// stopped through its manager: launchd would restart a killed process, and
// systemd must forget the unit before a manual start can reuse the socket.
func stopDaemon(opts options) (stopResult, error) {
	socket := strings.TrimSpace(opts.socket)
	if socket == "" {
		socket = paths.DefaultSocket()
	}
	pidPath := pidPathFor(socket)
	var res stopResult

	// Service managers only own the default socket. A custom socket is a
	// second daemon, and stopping the user service would stop the wrong one.
	if filepath.Clean(socket) == filepath.Clean(paths.DefaultSocket()) {
		if stopped, hint, err := stopSystemdUnit(); err != nil {
			return res, err
		} else if stopped {
			res.stopped = true
			res.hints = append(res.hints, hint)
		}
		if stopped, hint, err := stopLaunchdAgent(); err != nil {
			return res, err
		} else if stopped {
			res.stopped = true
			res.hints = append(res.hints, hint)
		}
	}

	pid, _ := readPIDFile(pidPath)
	if pid > 0 && processAlive(pid) {
		// A pid file alone is not proof: after a crash or a reboot the number
		// may belong to something else. Trust it only when the daemon is
		// listening, or when a service manager just stopped it.
		if res.stopped || socketLive(socket) {
			if err := terminatePID(pid); err != nil {
				return res, fmt.Errorf("stop daemon pid %d: %w", pid, err)
			}
			res.stopped = true
		}
	}
	removePIDFile(pidPath, pid)

	waitSocketGone(socket, daemonStopWait)
	if socketLive(socket) {
		if res.stopped {
			return res, fmt.Errorf("daemon is still listening on %s", socket)
		}
		return res, fmt.Errorf("a daemon listens on %s but left no pid file; stop it through its service manager or restart it with this version of tyd", socket)
	}
	// The daemon unlinks its socket on close. Drop one left by a crash.
	if _, err := os.Stat(socket); err == nil {
		_ = os.Remove(socket)
	}

	if res.stopped {
		res.hints = append(res.hints, "live sessions keep running; run 'tyd up' to adopt them again")
	}
	return res, nil
}

// pidPathFor keeps the pid next to the state it describes. The default path is
// the one install.sh writes, so both agree on a nohup daemon.
func pidPathFor(socket string) string {
	if strings.TrimSpace(socket) == "" {
		socket = paths.DefaultSocket()
	}
	if filepath.Clean(socket) == filepath.Clean(paths.DefaultSocket()) {
		return filepath.Join(paths.DefaultDir(), "tyd.pid")
	}
	return socket + ".pid"
}

func readPIDFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("unusable pid in %s", path)
	}
	return pid, nil
}

// removePIDFile deletes the file only when it still names pid. A newer daemon
// that already replaced it must keep its own file.
func removePIDFile(path string, pid int) {
	if pid > 0 {
		if cur, err := readPIDFile(path); err == nil && cur != pid {
			return
		}
	}
	_ = os.Remove(path)
}

func stopSystemdUnit() (bool, string, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, "", nil
	}
	if err := exec.Command("systemctl", "--user", "is-active", "--quiet", "tyd.service").Run(); err != nil {
		return false, "", nil
	}
	if out, err := exec.Command("systemctl", "--user", "stop", "tyd.service").CombinedOutput(); err != nil {
		return false, "", fmt.Errorf("systemctl --user stop tyd.service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return true, "started by systemd; start it again with 'systemctl --user start tyd'", nil
}

func stopLaunchdAgent() (bool, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, "", nil
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", "dev.getfda.tyd.plist")
	if _, err := os.Stat(plist); err != nil {
		return false, "", nil
	}
	if _, err := exec.LookPath("launchctl"); err != nil {
		return false, "", nil
	}
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil || !strings.Contains(string(out), "dev.getfda.tyd") {
		return false, "", nil
	}
	if out, err := exec.Command("launchctl", "unload", plist).CombinedOutput(); err != nil {
		return false, "", fmt.Errorf("launchctl unload %s: %v: %s", plist, err, strings.TrimSpace(string(out)))
	}
	return true, "unloaded dev.getfda.tyd; start it again with 'tyd up' or reinstall the service", nil
}

func terminatePID(pid int) error {
	if err := signalPID(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if waitProcessGone(pid, daemonStopWait) {
		return nil
	}
	_ = signalPID(pid, syscall.SIGKILL)
	if waitProcessGone(pid, time.Second) {
		return nil
	}
	return fmt.Errorf("pid %d did not exit", pid)
}

func signalPID(pid int, sig syscall.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}

func processAlive(pid int) bool {
	err := signalPID(pid, syscall.Signal(0))
	if err == nil {
		return true
	}
	// os.Process returns this after a concurrent Wait reaped the child.
	if errors.Is(err, os.ErrProcessDone) {
		return false
	}
	return !errors.Is(err, syscall.ESRCH)
}

func waitProcessGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(daemonPoll)
	}
	return !processAlive(pid)
}

func socketLive(path string) bool {
	c, err := net.DialTimeout("unix", path, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func waitSocketGone(path string, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err != nil {
			return
		}
		time.Sleep(daemonPoll)
	}
}
