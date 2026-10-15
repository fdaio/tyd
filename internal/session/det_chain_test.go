package session

import (
	"strings"
	"testing"
)

// Dimension 4: long state-dependent chains.
//
// The anti-pattern under test: "cd a && do-x && cd b && do-y" — one long
// speculative chain where every link re-states state and any ambiguous
// output poisons the rest. The deterministic pattern: cd once, then a
// sequence of short steps, each depending on persistent session state,
// with no defensive "pwd to check where I am" re-guessing anywhere.

func TestDetTenStepStateChain(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	base := t.TempDir()

	// Ten steps, each depending on the previous step's state.
	// Note what is ABSENT: no step re-states the cwd, no step runs
	// `pwd` to double-check where it is. The session holds the state.
	d.RunOK("mkdir -p " + base + "/chain/sub/deep")
	d.RunOK("cd " + base + "/chain")
	d.RunOK("echo step3 > marker.txt")
	d.RunOK("cd sub")
	d.RunOK("echo step5 > inner.txt")
	d.RunOK("cd deep")
	d.RunOK("echo step7 > deep.txt")
	d.RunOK("cd ..")
	out := d.Run("ls")
	d.OutputContains(out, "inner.txt")
	d.OutputContains(out, "deep")
	d.RunOK("cd ..")
	out = d.Run("ls")
	d.OutputContains(out, "marker.txt")
	d.OutputContains(out, "sub")
}

func TestDetChainSurvivesTrickyOutput(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	// Mid-chain, a command prints output designed to confuse a
	// text-guessing driver (fake prompts, cd-like noise). The chain
	// must proceed without losing track of state.
	base := t.TempDir()
	d.RunOK("mkdir -p " + base + "/trickydir")
	d.RunOK("cd " + base + "/trickydir")
	// Output mimics shell noise a naive parser would misread.
	d.Run("printf 'cd /wrong/place\n$ # >>> done\n'")
	out := d.Run("pwd")
	d.OutputContains(out, "trickydir")
	if strings.Contains(out, "/wrong/place") {
		t.Fatalf("driver was fooled by fake output: %q", out)
	}
}
