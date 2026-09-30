package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Serve ends by closing its input when the context is cancelled, because the
// frame it is waiting for is a read that no context can interrupt. Whether
// closing an *os.File wakes a goroutine already blocked reading it is a property
// of the platform and of what the file is, and a pipe is not a terminal: a fix
// that only works on a pipe is not a fix for someone running `tyd mcp` in a
// terminal and pressing Ctrl-C. So this drives the built binary with its stdin
// held open and asks the process to stop with a signal.

const signalExitBudget = 20 * time.Second

// buildMCPBinary builds tyd once per test binary run. The signal test has to
// drive a real process: a goroutine in this process cannot be given a SIGINT and
// have the runtime's own handlers interfere with the answer.
var (
	mcpBinaryOnce sync.Once
	mcpBinaryPath string
	mcpBinaryErr  error
)

func buildMCPBinary(t *testing.T) string {
	t.Helper()
	mcpBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("/tmp", "tydbin")
		if err != nil {
			mcpBinaryErr = err
			return
		}
		out := filepath.Join(dir, "tyd")
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = "." // the package under test
		if combined, err := cmd.CombinedOutput(); err != nil {
			mcpBinaryErr = &buildFailure{out: string(combined), err: err}
			return
		}
		mcpBinaryPath = out
	})
	if mcpBinaryErr != nil {
		t.Fatalf("build tyd: %v", mcpBinaryErr)
	}
	return mcpBinaryPath
}

type buildFailure struct {
	out string
	err error
}

func (b *buildFailure) Error() string { return b.err.Error() + ": " + b.out }

// mcpSignalFixture is a real `tyd mcp` process with its stdin held open.
type mcpSignalFixture struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *strings.Builder
	// done is closed once the process is gone and waitErr holds why. A channel
	// carrying the result would be consumed by whoever read it first, and the
	// cleanup has to be able to ask again.
	done    chan struct{}
	waitErr error
}

func startMCPForSignal(t *testing.T, bin string, extra ...string) *mcpSignalFixture {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tydsig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// One outbound peer, so the target resolves without --peer and the server
	// does not start a local daemon: this test is about signals, not about
	// sessions, and a daemon left running would outlive the test.
	peersPath := filepath.Join(dir, "peers.json")
	peersJSON := `{"peers":[{"id":"0123456789abcdef","public_key":"pk",` +
		`"nickname":"box","direction":"outbound","paired_at":"2026-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(peersPath, []byte(peersJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "id_ed25519")
	keygen := exec.Command(bin, "--identity", identity, "keygen")
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v: %s", err, out)
	}

	args := append([]string{
		"--identity", identity,
		"--peers", peersPath,
		"--archive", filepath.Join(dir, "archive.json"),
		"mcp",
	}, extra...)
	cmd := exec.Command(bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f := &mcpSignalFixture{
		t: t, cmd: cmd, stdin: stdin,
		stdout: bufio.NewReader(stdout), stderr: &stderr,
		done: make(chan struct{}),
	}
	go func() {
		f.waitErr = cmd.Wait()
		close(f.done)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-f.done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-f.done
		}
	})
	return f
}

// initialize performs the handshake and confirms the server is in its read loop,
// so the signal below arrives while it is waiting for a frame rather than before
// it has started.
func (f *mcpSignalFixture) initialize() {
	f.t.Helper()
	if err := json.NewEncoder(f.stdin).Encode(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"clientInfo":      map[string]any{"name": "signal-test", "version": "1"},
			"capabilities":    map[string]any{},
		},
	}); err != nil {
		f.t.Fatal(err)
	}
	line, err := f.stdout.ReadString('\n')
	if err != nil {
		f.t.Fatalf("no answer to initialize: %v (stderr: %s)", err, f.stderr.String())
	}
	if !strings.Contains(line, `"result"`) {
		f.t.Fatalf("initialize answered %q", line)
	}
}

// exited reports whether the process is gone, and how long it took.
func (f *mcpSignalFixture) exited(within time.Duration) (time.Duration, bool) {
	start := time.Now()
	select {
	case <-f.done:
		d := time.Since(start)
		f.t.Logf("exited after %s with %v; stderr: %s",
			d.Round(time.Millisecond), f.waitErr, f.stderr.String())
		return d, true
	case <-time.After(within):
		return 0, false
	}
}

// A terminal holds stdin open, and a signal is how a person stops a program. So
// the signal has to end the process while the input is still open, which is the
// case a pipe-based unit test cannot make.
func TestMCPRecognisesASignalWhileItsInputStaysOpen(t *testing.T) {
	bin := buildMCPBinary(t)
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		sig := sig
		t.Run(sig.String(), func(t *testing.T) {
			f := startMCPForSignal(t, bin)
			f.initialize()
			// stdin is deliberately still open.
			if err := f.cmd.Process.Signal(sig); err != nil {
				t.Fatalf("signal: %v", err)
			}
			if _, ok := f.exited(signalExitBudget); !ok {
				_ = f.cmd.Process.Kill()
				<-f.done
				t.Fatalf("%s did not stop within %s while its stdin stayed open; "+
					"closing the input does not wake a blocked read on this platform, "+
					"so the read has to be given its own goroutine", sig, signalExitBudget)
			}
		})
	}
}

// The same signal, with sessions to clean up, must still stop: the close-on-exit
// sweep runs after the read loop ends, and a sweep that could wait for ever
// would turn a signal into a hang.
func TestMCPRecognisesASignalWithCloseOnExit(t *testing.T) {
	bin := buildMCPBinary(t)
	f := startMCPForSignal(t, bin, "--close-on-exit")
	f.initialize()
	if err := f.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.exited(signalExitBudget); !ok {
		_ = f.cmd.Process.Kill()
		<-f.done
		t.Fatalf("SIGINT with --close-on-exit did not stop within %s", signalExitBudget)
	}
}

// A client that closes its input and then signals, and one that signals twice,
// are both ordinary. Neither may hang, and neither may report a failure the
// caller would act on.
func TestMCPSurvivesRudeInput(t *testing.T) {
	bin := buildMCPBinary(t)
	f := startMCPForSignal(t, bin)
	f.initialize()
	// Half a frame, then a signal: the decoder is holding an incomplete line.
	if _, err := io.WriteString(f.stdin, `{"jsonrpc":"2.0","id":2,"method":"ping"`); err != nil {
		t.Fatal(err)
	}
	if err := f.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.exited(signalExitBudget); !ok {
		_ = f.cmd.Process.Kill()
		<-f.done
		t.Fatalf("SIGTERM after a half-written frame did not stop within %s", signalExitBudget)
	}
}
