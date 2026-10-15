package session

import (
	"strings"
	"testing"
	"time"

	"tyd/internal/live"
)

// Dimension 2: output attribution.
//
// Send returns the cursor at which the input landed. Reading from that
// cursor yields exactly the output the input caused — no more, no less.
// The driver never has to guess which bytes belong to which command.

func TestDetSendCursorAttribution(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	// First command leaves output in the stream.
	d := NewAgentDriver(t, s)
	d.RunOK("echo first-command-output")

	// Second command: the read starts at Send's cursor, so the first
	// command's output cannot leak into this command's result.
	out := d.Run("echo second-command-output")
	if strings.Contains(out, "first-command-output") {
		t.Fatalf("attribution broken: earlier output leaked into later read: %q", out)
	}
	d.OutputContains(out, "second-command-output")
}

func TestDetFakePromptDoesNotFoolDriver(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()
	d := NewAgentDriver(t, s)

	// A command whose output contains text that LOOKS like a shell
	// prompt. A prompt-guessing driver would conclude the command
	// finished early or misattribute output. The cursor + unique marker
	// protocol must not be fooled.
	out := d.Run(`printf '$ \n# \n>>> \nreal-payload\n'`)
	d.OutputContains(out, "real-payload")
	// And the session is still healthy afterwards: state was not lost
	// to a misread.
	out2 := d.Run("echo still-alive")
	d.OutputContains(out2, "still-alive")
}

func TestDetReadReasonIsMatch(t *testing.T) {
	_, s, _, cleanup := newLiveSession(t)
	defer cleanup()

	reply, err := s.Send([]byte("echo reason-probe-token\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	// A declared Match condition: the read must come back BECAUSE the
	// token appeared (Reason == "match"), not because of a timeout or
	// because "some data arrived".
	res, err := s.Read(reply.Cursor, reply.Epoch, 5*time.Second, live.ReadConditions{
		Match: "reason-probe-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "match" {
		t.Fatalf("expected read reason %q, got %q", "match", res.Reason)
	}
}
