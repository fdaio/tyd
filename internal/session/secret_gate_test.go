package session

import (
	"errors"
	"strings"
	"testing"

	"tyd/internal/live"
)

// A secret write is a promise that the bytes will not be echoed. An agent that
// does not understand the flag ignores it rather than refusing, so the write lands
// in the clear and the promise is false. These tests pin the refusal that keeps
// that from happening.

// newSecretSession is a session with a known agent build, without a live agent, so
// the gate can be exercised on its own.
func newSecretSession(agentVersion int) *Session {
	s := &Session{ID: "s1", state: StateDetached, liveDir: "/nonexistent"}
	s.agentVersion = agentVersion
	return s
}

func TestASecretWriteIsRefusedWhenTheAgentVersionIsUnknown(t *testing.T) {
	// Zero is both "an agent older than the field existed" and "no reply seen
	// yet". Neither may write.
	for _, v := range []int{0, 1, live.MinSecretVersion - 1} {
		s := newSecretSession(v)
		_, err := s.Send([]byte("hunter2\n"), true)
		if err == nil {
			t.Fatalf("agent version %d wrote a secret", v)
		}
		if !strings.Contains(err.Error(), "refused") {
			t.Errorf("agent version %d: %v", v, err)
		}
	}
}

func TestTheRefusalSaysHowToGetUnblocked(t *testing.T) {
	// An agent that is merely old and one that has not spoken are different
	// situations with different answers, so the message has to tell them apart.
	old := newSecretSession(live.MinSecretVersion - 1)
	_, err := old.Send([]byte("x"), true)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "upgrade the agent") {
		t.Errorf("an old agent needs an upgrade named, got: %v", err)
	}

	unknown := newSecretSession(0)
	_, err = unknown.Send([]byte("x"), true)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "Read the session first") {
		t.Errorf("an agent that has not spoken needs a read named, got: %v", err)
	}
}

func TestASecretWriteGoesThroughWhenTheAgentIsNewEnough(t *testing.T) {
	s := newSecretSession(live.MinSecretVersion)
	if err := s.checkSecretPossible(); err != nil {
		t.Fatalf("refused a capable agent: %v", err)
	}
	// And one version above it, which is the same answer.
	s = newSecretSession(live.MinSecretVersion + 1)
	if err := s.checkSecretPossible(); err != nil {
		t.Fatalf("refused a newer agent: %v", err)
	}
}

func TestAnOrdinaryWriteIsNeverGatedOnTheAgentVersion(t *testing.T) {
	// The gate is about a promise, not about sends. An ordinary keystroke is
	// harmless against an agent that ignores a flag it has never heard of, so it
	// must not inherit the refusal — otherwise a rolling upgrade would stop models
	// from typing anything at all.
	s := newSecretSession(0)
	_, err := s.Send([]byte("echo hi\n"), false)
	// This session has no live agent, so a failure is expected; what must not
	// happen is the gate's own wording. Matching on "agent" would pass for the
	// unrelated "no running agent", which is why the phrases are the gate's.
	if err != nil {
		for _, phrase := range []string{"refused:", "dataplane version", "Read the session first"} {
			if strings.Contains(err.Error(), phrase) {
				t.Fatalf("an ordinary send was gated on the agent version: %v", err)
			}
		}
	}
}

func TestTheAgentVersionOnlyMovesForward(t *testing.T) {
	// A reply from an older build must not downgrade what is known, or a stale
	// reply could make a capable agent look incapable — safe, but wrong. The
	// direction that matters is the other one: a newer reply must be taken.
	s := newSecretSession(live.MinSecretVersion)
	s.noteAgentVersion(0)
	if err := s.checkSecretPossible(); err != nil {
		t.Errorf("a silent reply downgraded a known agent: %v", err)
	}
	s = newSecretSession(0)
	s.noteAgentVersion(live.MinSecretVersion)
	if err := s.checkSecretPossible(); err != nil {
		t.Errorf("a capable reply did not upgrade what was known: %v", err)
	}
	s.noteAgentVersion(1)
	if err := s.checkSecretPossible(); err != nil {
		t.Errorf("an older reply downgraded a capable agent: %v", err)
	}
}

func TestAGateRefusalIsNotMistakenForAnInUseSession(t *testing.T) {
	// The two refusals mean different things to a caller: one is transient and
	// about a person watching, the other is about the build.
	s := newSecretSession(0)
	_, err := s.Send([]byte("x"), true)
	if errors.Is(err, ErrSessionInUse) {
		t.Errorf("a version refusal reports itself as an attach: %v", err)
	}
}
