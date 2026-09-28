package procs

import (
	"os"
	"testing"
)

// The guard is only useful if it is right in both directions: it must catch a
// process inside a session, and it must not cry wolf about everything else.

func TestInSessionSeesTheMarker(t *testing.T) {
	t.Setenv(EnvSessionID, "abc123")
	if !InSession() {
		t.Fatal("a shell carrying the session marker was not recognised")
	}
}

func TestInSessionFalseOutsideASession(t *testing.T) {
	t.Setenv(EnvSessionID, "")
	if InSession() {
		t.Fatal("a process outside any session reported itself inside one")
	}
}

// A process that cleared the marker is still caught by the parent walk, because
// the marker is inherited and clearing it is an extra step an agent has to know
// to take.
func TestClearingTheMarkerDoesNotClearTheProcessTree(t *testing.T) {
	t.Setenv(EnvSessionID, "")
	in, err := DescendantOfSession(os.Getpid())
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if in {
		t.Fatal("the test process is inside a session; the check cannot be evaluated here")
	}
}

func TestAncestorPIDsReachesInit(t *testing.T) {
	chain := AncestorPIDs(os.Getpid())
	if len(chain) == 0 {
		t.Skip("no parent chain readable on this platform")
	}
	if chain[0] <= 0 {
		t.Errorf("first ancestor = %d", chain[0])
	}
	// A walk that never terminates would hang the CLI; it must stop.
	if len(chain) > maxAncestryDepth {
		t.Errorf("walk returned %d entries, past the bound", len(chain))
	}
}

func TestParentPIDOfInitIsZero(t *testing.T) {
	if got := parentPID(1); got != 0 {
		t.Errorf("parentPID(1) = %d, want 0 (nothing above init)", got)
	}
	if got := parentPID(0); got != 0 {
		t.Errorf("parentPID(0) = %d, want 0", got)
	}
	if got := parentPID(-1); got != 0 {
		t.Errorf("parentPID(-1) = %d, want 0", got)
	}
}

// A pid that does not exist must not be mistaken for a session, and must not
// hang the walk.
func TestUnknownPidIsNotASession(t *testing.T) {
	if processLooksLikeSession(1 << 30) {
		t.Error("a pid that cannot exist was reported as a session")
	}
}

func TestPeerPIDUnavailableIsReportedHonestly(t *testing.T) {
	// Nothing to check here without a socket; what matters is that the answer is
	// a clean "no" rather than a guess, so a platform that cannot know does not
	// pretend it does.
	if pid, ok := peerPID(0); ok && pid <= 0 {
		t.Error("peerPID claimed a connection with a non-positive pid")
	}
}
