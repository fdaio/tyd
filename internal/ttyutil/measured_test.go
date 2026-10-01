package ttyutil_test

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/creack/pty"

	"tyd/internal/ttyutil"
)

// InputMode's table came from knowledge of how these programs behave, not from
// watching them, and knowledge is not evidence. This file records what was
// actually observed, and the cheap test below holds the derivation to it.
//
// The measurements were taken on a pty, reading the master at the moment the
// prompt appeared — the same read production code makes, and the same moment the
// state matters. Reading later measures a program that has moved on: every row
// reads echo=on once its input has been consumed, because by then the child has
// usually exited and the pty is back at its defaults.

// measured is one row of the recorded table.
type measured struct {
	// Program is what was run.
	Program string `json:"program"`
	// Argv is the command, so a row can be repeated.
	Argv []string `json:"argv"`
	// Echo and Icanon are the line-discipline bits observed at the prompt. They
	// are pointers so that a row which was never measured carries no bits at all,
	// rather than a false pair that reads like an observation.
	Echo   *bool `json:"echo,omitempty"`
	Icanon *bool `json:"icanon,omitempty"`
	// ExpectSecret says what this row is in the table: whether the program was
	// asking for something a person should not have echoed.
	ExpectSecret bool `json:"expect_secret"`
	// Needs names a precondition an automated run cannot arrange, so a row that
	// needs one is left unmeasured on purpose rather than measured into a
	// meaningless value.
	Needs string `json:"needs,omitempty"`
	// NotMeasured explains a row that could not be measured here, so the gap is
	// recorded instead of quietly absent.
	NotMeasured string `json:"not_measured,omitempty"`
	// Note records why a row reads the way it does when that is not obvious.
	Note string `json:"note,omitempty"`
}

const measuredPath = "testdata/measured_prompts.json"

func boolPtr(b bool) *bool { return &b }

// updateTable rewrites the recorded table from a measurement run, so the evidence
// can be refreshed on a host that has the programs this one lacks.
var updateTable = flag.Bool("update", false, "rewrite testdata/"+measuredPath+" from what this run observed")

// table is what was observed on a macOS host, with python3 and sudo from the
// system and bash from Homebrew. Re-measure with:
//
//	TYD_MEASURE=1 go test ./internal/ttyutil -run TestMeasurePrompts
//	TYD_MEASURE=1 go test ./internal/ttyutil -run TestMeasurePrompts -update
func table() []measured {
	return []measured{
		{
			Program: "getpass", Argv: []string{"python3", "-c", "import getpass; getpass.getpass('Password: '); print('done')"},
			Echo: boolPtr(false), Icanon: boolPtr(true), ExpectSecret: true,
			Note: "the reference case: the program turns echo off and reads the line itself",
		},
		{
			Program: "bash read -s", Argv: []string{"bash", "--norc", "--noprofile", "-c", "read -rs -p 'Password: ' x; echo done"},
			Echo: boolPtr(false), Icanon: boolPtr(true), ExpectSecret: true,
		},
		{
			Program: "zsh read -s", Argv: []string{"zsh", "-f", "-c", "read -rs 'Password: ' x; echo done"},
			Echo: boolPtr(false), Icanon: boolPtr(true), ExpectSecret: true,
		},
		{
			Program: "sudo password", Argv: []string{"sudo", "-k", "-S", "true"},
			Echo: boolPtr(false), Icanon: boolPtr(true), ExpectSecret: true,
			Note: "the password is wrong on purpose; the prompt state is reached before it is checked",
		},
		{
			Program: "bash plain read", Argv: []string{"bash", "--norc", "--noprofile", "-c", "read -r -p 'Name: ' x; echo done"},
			Echo: boolPtr(true), Icanon: boolPtr(true), ExpectSecret: false,
			Note: "the counter-case: a prompt that looks the same and is not a secret",
		},
		{
			Program: "raw pty", Argv: []string{"sh", "-c", "stty raw -echo; cat"},
			Echo: boolPtr(false), Icanon: boolPtr(false), ExpectSecret: false,
			Note: "what a full-screen program and a nested terminal produce: app_managed, and why " +
				"a secret cannot be sent through one",
		},
		{
			Program: "vim full screen", Argv: []string{"vim", "-u", "NONE", "-n"},
			Echo: boolPtr(false), Icanon: boolPtr(false), ExpectSecret: false,
		},
		{
			Program: "nothing running", Argv: []string{"cat"},
			Echo: boolPtr(true), Icanon: boolPtr(true), ExpectSecret: false,
			Note: "the default a freshly created pty starts in",
		},
		{
			// The one row that needs a host with password authentication. Running
			// ssh here is not a substitute: it starts, prints "connection refused",
			// and a measurement of that reads as an ordinary echoing terminal, which
			// would look like evidence that ssh does not disable echo. It does not.
			Program:      "ssh password",
			Argv:         []string{"ssh", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "root@127.0.0.1"},
			ExpectSecret: true,
			Needs:        "a host that offers password authentication; a refused connection never reaches the prompt",
		},
	}
}

// TestMeasuredPromptsHoldTheDerivation is the cheap test. It runs on every build
// and asserts two things: that the mode derived from the recorded bits is what the
// table says it should be, and that no row the table marks as a secret prompt
// derives from an echoing terminal.
//
// The second half is the one that matters. If a program turns out to ask for a
// secret while the terminal echoes, the table cannot help us — and that has to
// fail here rather than be discovered at a prompt.
func TestMeasuredPromptsHoldTheDerivation(t *testing.T) {
	rows := table()
	if len(rows) == 0 {
		t.Fatal("the measured table is empty")
	}
	for _, r := range rows {
		t.Run(r.Program, func(t *testing.T) {
			if r.Needs != "" {
				t.Skip(r.Needs)
			}
			if r.NotMeasured != "" {
				t.Skip(r.NotMeasured)
			}
			if r.Echo == nil || r.Icanon == nil {
				t.Fatalf("%s is marked as needing %q but has no measured bits", r.Program, r.Needs)
			}
			state := ttyutil.EchoState{Echo: *r.Echo, Icanon: *r.Icanon}
			mode := state.InputMode()

			secret := mode == ttyutil.InputSecretLikely
			if secret != r.ExpectSecret {
				t.Errorf("echo=%v icanon=%v derives %q, so secret=%v, but the table says secret=%v",
					r.Echo, r.Icanon, mode, secret, r.ExpectSecret)
			}
			if r.ExpectSecret && state.Echo {
				t.Errorf("this row asks for a secret while the terminal echoes, " +
					"so no terminal state can tell a caller it is a secret")
			}
		})
	}
}

// TestTheDerivedTableIsTotal pins the three-way classification, including the case
// the measurements could not produce on this host: echo on with ICANON off, which
// is a program that turned off line editing but left the driver echoing.
func TestTheDerivedTableIsTotal(t *testing.T) {
	for _, tc := range []struct {
		echo, icanon bool
		want         ttyutil.InputMode
	}{
		{true, true, ttyutil.InputEcho},
		{false, true, ttyutil.InputSecretLikely},
		{false, false, ttyutil.InputAppManaged},
		{true, false, ttyutil.InputEcho},
	} {
		got := ttyutil.EchoState{Echo: tc.echo, Icanon: tc.icanon}.InputMode()
		if got != tc.want {
			t.Errorf("echo=%v icanon=%v is %q, want %q", tc.echo, tc.icanon, got, tc.want)
		}
	}
}

// TestMeasurePrompts re-measures the table against real programs on a real pty.
// It is skipped unless TYD_MEASURE is set, because it starts real programs and
// takes about half a minute.
//
// With -update it rewrites testdata/measured_prompts.json from what it saw, which
// is how the table is kept honest on a host with the programs this one lacks.
func TestMeasurePrompts(t *testing.T) {
	if os.Getenv("TYD_MEASURE") == "" {
		t.Skip("set TYD_MEASURE=1 to re-measure; this starts real programs")
	}
	if runtime.GOOS == "windows" {
		t.Skip("a pty is not available here")
	}
	update := *updateTable

	rows := table()
	for i, r := range rows {
		if r.Needs != "" {
			t.Logf("%-22s needs %s", r.Program, r.Needs)
			continue
		}
		if _, err := exec.LookPath(r.Argv[0]); err != nil {
			rows[i].NotMeasured = "not installed on this host: " + err.Error()
			t.Logf("%-22s not installed", r.Program)
			continue
		}
		state, err := measure(r.Argv)
		if err != nil {
			rows[i].NotMeasured = err.Error()
			t.Logf("%-22s %v", r.Program, err)
			continue
		}
		rows[i].Echo, rows[i].Icanon = boolPtr(state.Echo), boolPtr(state.Icanon)
		rows[i].NotMeasured = ""
		t.Logf("%-22s echo=%-5v icanon=%-5v mode=%s", r.Program, state.Echo, state.Icanon, state.InputMode())
	}

	if update {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Clean(measuredPath), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", measuredPath)
		return
	}
	for i, r := range rows {
		if r.NotMeasured != "" {
			t.Logf("%-22s could not be measured: %s", r.Program, r.NotMeasured)
			continue
		}
		was := table()[i]
		if r.Echo == nil || was.Echo == nil {
			continue
		}
		if *r.Echo != *was.Echo || *r.Icanon != *was.Icanon {
			t.Errorf("%-22s now reads echo=%v icanon=%v, the table says echo=%v icanon=%v",
				r.Program, *r.Echo, *r.Icanon, *was.Echo, *was.Icanon)
		}
	}
}

// measure runs argv on a pty and reads the line discipline from the master at the
// moment the program has settled, before anything is typed.
func measure(argv []string) (ttyutil.EchoState, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return ttyutil.EchoState{}, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			if _, err := ptmx.Read(buf); err != nil {
				return
			}
		}
	}()
	// Long enough for the program to start and, where it waits, to reach its
	// prompt. Short enough that the measurement is not a slow test.
	time.Sleep(1500 * time.Millisecond)
	state, err := ttyutil.ReadEchoState(int(ptmx.Fd()))
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	_ = ptmx.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return state, err
}
