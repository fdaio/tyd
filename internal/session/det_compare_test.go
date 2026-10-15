package session

// Dimension 6: the control experiment.
//
// The first five dimensions prove tyd's contract is deterministic. This
// one quantifies the alternative: what happens when an agent drives a
// shell the way agents do TODAY — stateless one-shot exec, state
// threaded through by hand, completion by process exit, cwd tracked by
// PARSING the commands it sent.
//
// The NaiveDriver below is not a strawman. It is the honest pattern:
//   - each Run is a fresh `sh -c` (like every agent exec tool)
//   - state is chained: `cd <tracked-cwd> && <cmd>`
//   - the tracked cwd is updated by parsing `cd` out of the command
//     string — because there is no session to hold it
//
// That parsing IS the speculation. When it diverges from reality
// (a failed cd, a cd buried in a chain, output that looks like a cd),
// every later command runs in the wrong place and the agent cannot
// tell — there is no cursor, no epoch, nothing to check against.
//
// The benchmark runs the same tasks through both drivers and reports
// where guessing fails. tyd's column must be all PASS; that is the
// mission quantified.

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// NaiveDriver drives a shell the pre-tyd way: stateless exec, manual
// state tracking by command parsing.
type NaiveDriver struct {
	t   *testing.T
	cwd string // GUESSED cwd, updated by parsing cd commands
}

func NewNaiveDriver(t *testing.T, cwd string) *NaiveDriver {
	t.Helper()
	return &NaiveDriver{t: t, cwd: cwd}
}

// Run executes cmd in a fresh shell, chained onto the tracked cwd.
// The tracked cwd is then updated by a best-effort parse of `cd`
// directives in cmd — the speculation under test.
func (d *NaiveDriver) Run(cmd string) string {
	d.t.Helper()
	full := fmt.Sprintf("cd %q && %s", d.cwd, cmd)
	out, err := exec.Command("/bin/sh", "-c", full).CombinedOutput()
	if err != nil {
		// A failed command does not stop a naive driver; it presses on
		// with whatever state it thinks it has. That is the point.
		d.t.Logf("naive command failed (continuing): %q: %v", cmd, err)
	}
	d.guessCwd(cmd)
	return string(out)
}

// guessCwd updates the tracked cwd by parsing cd out of the command.
// This is what an agent without a session must do, and it is fragile:
// a failed cd, a cd with variables, or a cd inside a conditional all
// defeat it — silently.
func (d *NaiveDriver) guessCwd(cmd string) {
	// Naive parse: look for "cd <dir>" tokens.
	// Handles: cd /x, cd /x && ..., ; cd /x ;
	// Misses: cd failed, cd $VAR, cd in if/for, pushd/popd.
	tokens := strings.Fields(cmd)
	for i, tok := range tokens {
		if tok == "cd" && i+1 < len(tokens) {
			target := strings.Trim(tokens[i+1], `"';&|`)
			if target == "" || strings.HasPrefix(target, "$") {
				continue
			}
			if filepath.IsAbs(target) {
				d.cwd = target
			} else {
				d.cwd = filepath.Join(d.cwd, target)
			}
		}
	}
	// Normalize .. and .
	d.cwd = filepath.Clean(d.cwd)
}

// compareResult is one row of the benchmark table.
type compareResult struct {
	task     string
	naive    string // PASS / FAIL (reason)
	tyd      string
	naiveOut string
	tydOut   string
}

func (r compareResult) String() string {
	return fmt.Sprintf("%-24s | %-28s | %-10s", r.task, r.naive, r.tyd)
}

func printCompareTable(t *testing.T, rows []compareResult) {
	t.Helper()
	t.Logf("\n%-24s | %-28s | %-10s", "task", "naive (guess)", "tyd")
	t.Logf("%s", strings.Repeat("-", 70))
	for _, r := range rows {
		t.Logf("%s", r.String())
	}
}

// TestDetCompare is the control experiment. Each task runs through the
// naive driver (guess) and the tyd driver (deterministic); the table
// shows where guessing fails.
func TestDetCompare(t *testing.T) {
	var rows []compareResult

	// Task 1: cd then pwd. The simplest stateful operation.
	rows = append(rows, compareCdThenPwd(t))

	// Task 2: the 10-step chain.
	rows = append(rows, compareLongChain(t))

	// Task 3: the trap — a failed cd mid-chain.
	// The naive driver parses "cd /nonexistent" and UPDATES its tracked
	// cwd even though the cd failed. Every later command is then wrong.
	rows = append(rows, compareFailedCd(t))

	// Task 4: output containing cd-like text confuses the parser.
	rows = append(rows, compareCdNoise(t))

	printCompareTable(t, rows)

	// The mission quantified: tyd must have zero guess-failures.
	for _, r := range rows {
		if r.tyd != "PASS" {
			t.Errorf("tyd failed task %q: %s", r.task, r.tydOut)
		}
	}
}

func compareCdThenPwd(t *testing.T) compareResult {
	t.Helper()
	r := compareResult{task: "cd then pwd"}

	// Naive.
	nd := NewNaiveDriver(t, "/tmp")
	dir := t.TempDir()
	nd.Run("cd " + dir)
	out := nd.Run("pwd")
	if strings.Contains(out, dir) {
		r.naive = "PASS"
	} else {
		r.naive = "FAIL (lost cwd)"
	}
	r.naiveOut = out

	// tyd.
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)
	d.RunOK("cd " + dir)
	tout := d.Run("pwd")
	if strings.Contains(tout, dir) {
		r.tyd = "PASS"
	} else {
		r.tyd = "FAIL"
	}
	r.tydOut = tout
	return r
}

func compareLongChain(t *testing.T) compareResult {
	t.Helper()
	r := compareResult{task: "10-step chain"}

	base := t.TempDir()

	// Naive: every step chains cd manually; cwd tracked by parsing.
	nd := NewNaiveDriver(t, "/tmp")
	nd.Run("mkdir -p " + base + "/chain/sub/deep")
	nd.Run("cd " + base + "/chain")
	nd.Run("echo step3 > marker.txt")
	nd.Run("cd sub")
	nd.Run("echo step5 > inner.txt")
	nd.Run("cd deep")
	nd.Run("echo step7 > deep.txt")
	nd.Run("cd ..")
	out := nd.Run("ls")
	ndOk := strings.Contains(out, "inner.txt")
	nd.Run("cd ..")
	out2 := nd.Run("ls")
	ndOk = ndOk && strings.Contains(out2, "marker.txt")
	if ndOk {
		r.naive = "PASS"
	} else {
		r.naive = "FAIL (chain broke)"
	}
	r.naiveOut = out + "\n" + out2

	// tyd: the session holds the state.
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)
	d.RunOK("mkdir -p " + base + "/chain/sub/deep")
	d.RunOK("cd " + base + "/chain")
	d.RunOK("echo step3 > marker.txt")
	d.RunOK("cd sub")
	d.RunOK("echo step5 > inner.txt")
	d.RunOK("cd deep")
	d.RunOK("echo step7 > deep.txt")
	d.RunOK("cd ..")
	tout := d.Run("ls")
	tydOk := strings.Contains(tout, "inner.txt")
	d.RunOK("cd ..")
	tout2 := d.Run("ls")
	tydOk = tydOk && strings.Contains(tout2, "marker.txt")
	if tydOk {
		r.tyd = "PASS"
	} else {
		r.tyd = "FAIL"
	}
	r.tydOut = tout + "\n" + tout2
	return r
}

func compareFailedCd(t *testing.T) compareResult {
	t.Helper()
	r := compareResult{task: "failed cd mid-chain"}

	dir := t.TempDir()

	// Naive: cd to a nonexistent dir FAILS, but the parser still
	// updates the tracked cwd. The next pwd then runs in the WRONG
	// place — via the chained `cd <wrong> && pwd`, which itself fails,
	// producing confusing output.
	nd := NewNaiveDriver(t, "/tmp")
	nd.Run("cd " + dir)           // ok
	nd.Run("cd /nonexistent-xyz") // fails, but parser updates cwd anyway
	out := nd.Run("pwd")
	// The naive driver THINKS it is in /nonexistent-xyz.
	if nd.cwd == "/nonexistent-xyz" && !strings.Contains(out, dir) {
		r.naive = "FAIL (tracked cwd diverged)"
	} else if strings.Contains(out, dir) {
		r.naive = "PASS"
	} else {
		r.naive = "FAIL (confused)"
	}
	r.naiveOut = fmt.Sprintf("tracked=%q out=%q", nd.cwd, out)

	// tyd: the failed cd does not move the session; pwd is still right.
	// Note: RunOK would fail the test on the bad cd, so use Run and
	// check the state directly — the point is the SESSION never lied.
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)
	d.RunOK("cd " + dir)
	d.Run("cd /nonexistent-xyz") // fails; session stays put
	tout := d.Run("pwd")
	if strings.Contains(tout, dir) {
		r.tyd = "PASS"
	} else {
		r.tyd = "FAIL"
	}
	r.tydOut = tout
	return r
}

func compareCdNoise(t *testing.T) compareResult {
	t.Helper()
	r := compareResult{task: "cd that never executes"}

	dir := t.TempDir()

	// Naive: `false && cd /wrongplace` — the cd NEVER executes
	// (false short-circuits the &&), but the parser sees the tokens
	// "cd /wrongplace" and updates the tracked cwd anyway.
	// Silent divergence, same class as the failed cd.
	nd := NewNaiveDriver(t, "/tmp")
	nd.Run("cd " + dir)
	nd.Run("false && cd /wrongplace")
	out := nd.Run("pwd")
	if nd.cwd == "/wrongplace" {
		r.naive = "FAIL (parsed unexecuted cd)"
	} else if strings.Contains(out, dir) {
		r.naive = "PASS"
	} else {
		r.naive = "FAIL (confused)"
	}
	r.naiveOut = fmt.Sprintf("tracked=%q out=%q", nd.cwd, out)

	// tyd: the session knows the cd never ran; no parsing involved.
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)
	d.RunOK("cd " + dir)
	d.Run("false && cd /wrongplace") // exits 1; cd never executes
	tout := d.Run("pwd")
	if strings.Contains(tout, dir) {
		r.tyd = "PASS"
	} else {
		r.tyd = "FAIL"
	}
	r.tydOut = tout
	return r
}

// TestDetCompareRepeated runs the trap tasks several times to show the
// failure is systematic, not a flake.
func TestDetCompareRepeated(t *testing.T) {
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("round-%d", i), func(t *testing.T) {
			r := compareFailedCd(t)
			t.Logf("naive: %s | tyd: %s", r.naive, r.tyd)
			if r.tyd != "PASS" {
				t.Errorf("tyd failed: %q", r.tydOut)
			}
			// The naive driver MUST fail this systematically:
			// its parser cannot distinguish a failed cd.
			if !strings.HasPrefix(r.naive, "FAIL") {
				t.Errorf("expected naive to fail the failed-cd trap, got %q", r.naive)
			}
		})
	}
}
