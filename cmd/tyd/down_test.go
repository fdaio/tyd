package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tyd/internal/paths"
)

func writePIDForTest(t *testing.T, path string, pid int) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fakeCommand(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestPIDPathFor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	def := paths.DefaultSocket()
	if got, want := pidPathFor(def), filepath.Join(home, ".tyd", "tyd.pid"); got != want {
		t.Fatalf("default pid path = %q, want %q", got, want)
	}
	custom := filepath.Join(home, "other.sock")
	if got, want := pidPathFor(custom), custom+".pid"; got != want {
		t.Fatalf("custom pid path = %q, want %q", got, want)
	}
}

// A manual daemon (the transcript's `tyd up`) leaves a pid file next to its
// custom socket; down signals it and cleans both the pid and the socket.
func TestStopDaemonManual(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "tyd.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	writePIDForTest(t, pidPathFor(socket), child.Process.Pid)

	// Stand in for the daemon's listener: it goes away when the process exits,
	// which is what down waits for.
	done := make(chan struct{})
	go func() {
		_ = child.Wait()
		_ = ln.Close()
		_ = os.Remove(socket)
		close(done)
	}()

	res, err := stopDaemon(options{socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if !res.stopped {
		t.Fatal("daemon was not reported as stopped")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("child process did not exit")
	}
	if _, err := os.Stat(pidPathFor(socket)); !os.IsNotExist(err) {
		t.Fatalf("pid file still exists: %v", err)
	}
}

func TestStopDaemonNotRunning(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "tyd.sock")
	res, err := stopDaemon(options{socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if res.stopped {
		t.Fatal("reported a stop when nothing was running")
	}
}

// A stale pid after a crash or reboot may name an unrelated process. Without a
// live socket, down must not signal it.
func TestStopDaemonIgnoresStalePID(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "tyd.sock")
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})
	writePIDForTest(t, pidPathFor(socket), child.Process.Pid)

	res, err := stopDaemon(options{socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if res.stopped {
		t.Fatal("a stale pid without a listening socket was treated as a daemon")
	}
	if !processAlive(child.Process.Pid) {
		t.Fatal("down signalled a process that was not a listening daemon")
	}
	if _, err := os.Stat(pidPathFor(socket)); !os.IsNotExist(err) {
		t.Fatalf("stale pid file was not cleaned: %v", err)
	}
}

func TestStopDaemonSystemd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls.log")
	fakeCommand(t, bin, "systemctl", `
case "$2" in
  is-active) exit 0 ;;
  stop) echo "stop" >> "$FAKE_LOG"; exit 0 ;;
esac
exit 1`)
	fakeCommand(t, bin, "launchctl", "exit 1")
	t.Setenv("FAKE_LOG", logPath)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, err := stopDaemon(options{socket: paths.DefaultSocket()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.stopped {
		t.Fatal("systemd unit was not reported as stopped")
	}
	if hints := strings.Join(res.hints, " "); !strings.Contains(hints, "systemd") {
		t.Fatalf("hints do not mention systemd: %v", res.hints)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "stop") {
		t.Fatalf("systemctl stop was not called: %q", calls)
	}
}

func TestStopDaemonLaunchd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	plist := filepath.Join(home, "Library", "LaunchAgents", "dev.getfda.tyd.plist")
	if err := os.MkdirAll(filepath.Dir(plist), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logPath := filepath.Join(bin, "calls.log")
	fakeCommand(t, bin, "launchctl", `
case "$1" in
  list) echo "- 0 dev.getfda.tyd"; exit 0 ;;
  unload) echo "unload $2" >> "$FAKE_LOG"; exit 0 ;;
esac
exit 1`)
	fakeCommand(t, bin, "systemctl", "exit 1")
	t.Setenv("FAKE_LOG", logPath)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, err := stopDaemon(options{socket: paths.DefaultSocket()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.stopped {
		t.Fatal("launchd agent was not reported as stopped")
	}
	if hints := strings.Join(res.hints, " "); !strings.Contains(hints, "unloaded") {
		t.Fatalf("hints do not mention the unloaded agent: %v", res.hints)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "unload") {
		t.Fatalf("launchctl unload was not called: %q", calls)
	}
}
