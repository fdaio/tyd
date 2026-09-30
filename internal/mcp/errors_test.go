package mcp

import (
	"errors"
	"strings"
	"testing"

	daemon "tyd/internal/server"
)

// The number quoted to a model is the target's own wait, so a change to the
// server's default cannot leave the message promising less time than the target
// actually gives.
func TestQuotedApprovalWindowMatchesTheTarget(t *testing.T) {
	if approvalWindow != daemon.DefaultApprovalTTL {
		t.Fatalf("quoted window %s, target default %s", approvalWindow, daemon.DefaultApprovalTTL)
	}
}

// A pre-mode target spends each approval on one request. A model that is told
// only "waiting for approval" approves once and then reports a broken target,
// so the message has to say what approving buys.
func TestPendingApprovalSaysApprovalIsSpentPerRequest(t *testing.T) {
	err := mapError(errors.New("attach pending approval; ask the operator to run: tyd session approve abc"),
		Session{ID: "abc"})
	if err == nil {
		t.Fatal("a pending approval must be an error the model can act on")
	}
	msg := err.Error()
	for _, want := range []string{
		"tyd session approve abc",
		"one request at a time",
		"each send and each read",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message is missing %q: %s", want, msg)
		}
	}
}
