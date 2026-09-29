package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tyd/internal/client"
	"tyd/internal/transport"
)

// startLocalDaemonFn launches a background `tyd up`. Tests replace it.
var startLocalDaemonFn = startLocalDaemonProcess

func localDaemonReady(socket string) bool {
	socket = strings.TrimSpace(socket)
	if socket == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ensureLocalDaemon starts a local tyd up when the CLI needs the unix socket
// and nothing is listening. Peer / --addr targets are left alone so clients
// never require a resident local daemon.
func ensureLocalDaemon(opts options, ep client.Endpoint) error {
	if ep.Kind != transport.KindUnix && ep.Kind != "" {
		return nil
	}
	sock := strings.TrimSpace(ep.Address)
	if sock == "" {
		sock = opts.socket
	}
	if localDaemonReady(sock) {
		return nil
	}
	fmt.Fprintln(os.Stderr, "local daemon not running; starting tyd up")
	if err := startLocalDaemonFn(opts); err != nil {
		return fmt.Errorf("start local daemon: %w", err)
	}
	if err := waitLocalDaemon(sock, 15*time.Second); err != nil {
		return err
	}
	return nil
}

func waitLocalDaemon(socket string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if localDaemonReady(socket) {
			return nil
		}
		last = fmt.Errorf("not listening")
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return fmt.Errorf("local daemon not ready on %s: %w", socket, last)
}

func startLocalDaemonProcess(opts options) error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{
		"--socket", opts.socket,
		"--identity", opts.identity,
		"--trust", opts.trust,
		"--peers", opts.peers,
		"--listen", opts.listen,
		"--data-listen", opts.dataListen,
		"--live", opts.live,
		"--platform", opts.platform,
		"--relay", opts.relay,
	}
	if opts.advertise != "" {
		args = append(args, "--advertise", opts.advertise)
	}
	if opts.cert != "" {
		args = append(args, "--tls-cert", opts.cert)
	}
	if opts.key != "" {
		args = append(args, "--tls-key", opts.key)
	}
	if opts.auditLog != "" {
		args = append(args, "--audit-log", opts.auditLog)
	}
	if opts.sessionIdle > 0 {
		args = append(args, "--session-idle-timeout", opts.sessionIdle.String())
	}
	if opts.outputLogMax > 0 {
		args = append(args, "--session-output-log-max", strconv.FormatInt(opts.outputLogMax, 10))
		if opts.sessionSendTimeout > 0 {
			args = append(args, "--session-send-timeout", opts.sessionSendTimeout.String())
		}
	}
	args = append(args, "up")

	if err := os.MkdirAll(filepath.Dir(opts.socket), 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(filepath.Dir(opts.socket), "tyd.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(execPath, args...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		return err
	}
	_ = logf.Close()
	go func() { _ = cmd.Wait() }()
	return nil
}
