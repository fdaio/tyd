package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// call runs one tool and returns the text and the structured content.
func call(t *testing.T, s *server, name string, a args) (string, *result, error) {
	t.Helper()
	text, structured, err := s.dispatch(context.Background(), name, a)
	if err != nil {
		return text, nil, err
	}
	res, ok := structured.(*result)
	if !ok {
		t.Fatalf("%s: structured content is %T, want *result", name, structured)
	}
	return text, res, nil
}

func TestOpenThenSend(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)

	text, res, err := call(t, s, "session_open", args{"name": "build"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Session != "build" {
		t.Fatalf("session = %q", res.Session)
	}
	if res.HumanAttach != "tyd session attach build" {
		t.Fatalf("human_attach = %q", res.HumanAttach)
	}

	// The argument holds a real newline, which is what a JSON string carries and
	// what a shell needs at the end of a command.
	_, res, err = call(t, s, "session_send", args{
		"session": "build",
		"data":    "echo hi\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written == nil || *res.Written != len("echo hi\n") {
		t.Fatalf("written = %v, want %d", res.Written, len("echo hi\n"))
	}
	if !strings.Contains(res.Output, "echo hi") {
		t.Fatalf("output = %q", res.Output)
	}
	_ = text
}

func TestOpenAssignsAgentNames(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	for i := 1; i <= 3; i++ {
		_, res, err := call(t, s, "session_open", args{})
		if err != nil {
			t.Fatal(err)
		}
		want := "agent-" + string(rune('0'+i))
		if res.Session != want {
			t.Fatalf("open %d: session = %q, want %q", i, res.Session, want)
		}
	}
}

func TestOpenRefusesADuplicateName(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := call(t, s, "session_open", args{"name": "build"})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("err = %v, want a refusal about the name", err)
	}
}

func TestOpenRespectsTheSessionCap(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, func(o *Options) { o.MaxSessions = 2 })
	for i := 0; i < 2; i++ {
		if _, _, err := call(t, s, "session_open", args{}); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	_, _, err := call(t, s, "session_open", args{})
	if _, ok := ToolError(err); !ok {
		t.Fatalf("err = %v, want a tool error the model can act on", err)
	}
	if !strings.Contains(err.Error(), "--max-sessions") {
		t.Fatalf("err = %v, want it to name the way out", err)
	}
}

func TestOpenSurvivesAFailedFirstRead(t *testing.T) {
	f := newFakeBackend()
	f.readErr = errBoom
	s := testServer(f, nil)
	text, res, err := call(t, s, "session_open", args{"name": "build"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "read_failed" {
		t.Fatalf("reason = %q, want read_failed: the session exists either way", res.Reason)
	}
	if !strings.Contains(text, "tyd session attach build") {
		t.Fatalf("the takeover command must survive a failed read: %q", text)
	}
}

var errBoom = errorString("boom")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestSendRefusesAnOversizePayload(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := call(t, s, "session_send", args{
		"session": "agent-1",
		"data":    strings.Repeat("x", maxSendBytes+1),
	})
	if err == nil || !strings.Contains(err.Error(), "Split it into several sends") {
		t.Fatalf("err = %v, want a message that says how to split it", err)
	}
}

func TestSendEscapesAreExpanded(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	_, res, err := call(t, s, "session_send", args{
		"session": "agent-1", "data": `a\tb\x03`, "escapes": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Written == nil || *res.Written != 4 {
		t.Fatalf("written = %v, want 4 bytes", res.Written)
	}
}

func TestSendLeavesABackslashAloneByDefault(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	// A JSON string already carries a newline, so a second unescape layer would
	// only misread a command that legitimately holds a backslash.
	_, _, err := call(t, s, "session_send", args{
		"session": "agent-1", "data": "sed -E 's/\\t/ /g'\n",
	})
	if err != nil {
		t.Fatalf("a command holding a backslash must go through by default: %v", err)
	}
}

func TestSendRefusesABadEscapeOnlyWhenAsked(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	// escapes=true is a statement that the argument is a key sequence, so an
	// unknown escape is a typo worth reporting rather than typing silently.
	_, _, err := call(t, s, "session_send", args{
		"session": "agent-1", "data": `a\qb`, "escapes": true,
	})
	if err == nil {
		t.Fatal("an unknown escape must stay an error")
	}
	for _, want := range []string{`\xHH`, "escapes=false"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	// The same argument is fine to type when no unescaping was asked for.
	if _, _, err := call(t, s, "session_send", args{"session": "agent-1", "data": `a\qb`}); err != nil {
		t.Fatalf("with escapes off the backslash is just a backslash: %v", err)
	}
}

func TestSendWaitDefaults(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	f.readWait, f.readCond = nil, nil
	if _, _, err := call(t, s, "session_send", args{"session": "agent-1", "data": "ls\n"}); err != nil {
		t.Fatal(err)
	}
	if len(f.readWait) != 1 {
		t.Fatalf("reads = %d, want 1", len(f.readWait))
	}
	if f.readWait[0] != defaultSendWaitMS*time.Millisecond {
		t.Fatalf("wait = %v, want %v", f.readWait[0], defaultSendWaitMS*time.Millisecond)
	}
	if f.readCond[0].IdleMS != defaultSendIdleMS {
		t.Fatalf("idle = %d, want %d", f.readCond[0].IdleMS, defaultSendIdleMS)
	}
}

func TestSendMatchReplacesTheIdleDefault(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	f.readWait, f.readCond = nil, nil
	_, _, err := call(t, s, "session_send", args{
		"session": "agent-1",
		"data":    "sudo -v\n",
		"wait":    map[string]any{"match": "password:", "wait_ms": float64(5000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.readCond[0].IdleMS != 0 {
		t.Fatalf("idle = %d: a match is the caller's own condition, not a second one", f.readCond[0].IdleMS)
	}
	if f.readCond[0].Match != "password:" {
		t.Fatalf("match = %q", f.readCond[0].Match)
	}
}

func TestReadDefaultsToTwoSeconds(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	f.readWait, f.readCond = nil, nil
	if _, _, err := call(t, s, "session_read", args{"session": "agent-1"}); err != nil {
		t.Fatal(err)
	}
	if f.readWait[0] != defaultReadWaitMS*time.Millisecond {
		t.Fatalf("wait = %v, want %v", f.readWait[0], defaultReadWaitMS*time.Millisecond)
	}
	if f.readCond[0].Any() {
		t.Fatalf("cond = %+v, want no condition by default", f.readCond[0])
	}
}

func TestReadRejectsAWaitOverTheTargetCeiling(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := call(t, s, "session_read", args{
		"session": "agent-1",
		"wait":    map[string]any{"wait_ms": float64(maxWaitMS + 1)},
	})
	if err == nil || !strings.Contains(err.Error(), "30000") {
		t.Fatalf("err = %v, want the target ceiling named", err)
	}
}

func TestExplicitCursorDoesNotMoveTheSavedOne(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := call(t, s, "session_send", args{"session": "agent-1", "data": "echo hi\n"}); err != nil {
		t.Fatal(err)
	}
	st := s.state("/sess1")
	if st.cursor == 0 {
		t.Fatal("the first read should have saved a cursor")
	}
	saved := st.cursor

	// A re-read of the start returns the whole stream again.
	_, res, err := call(t, s, "session_read", args{"session": "agent-1", "cursor": float64(0)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Cursor == 0 {
		t.Fatalf("cursor = %d; a re-read reports where it stopped", res.Cursor)
	}
	if st.cursor != saved {
		t.Fatalf("saved cursor moved to %d, want %d: a re-read must be repeatable", st.cursor, saved)
	}
}

func TestReadFirstContactIsTrimmed(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	// A session that already holds a long log before this process ever looks.
	big := strings.Repeat("old output line\n", 4000)
	f.sessions["sess1"] = &fakeSession{id: "sess1", alias: "build", log: []byte(big)}
	f.alias["build"] = "sess1"

	_, res, err := call(t, s, "session_read", args{"session": "build"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Output) > firstContactLimit+512 {
		t.Fatalf("first contact returned %d bytes, want about %d", len(res.Output), firstContactLimit)
	}
	if res.Gap == 0 {
		t.Fatal("the trimmed prefix must be reported as a gap, not hidden")
	}
	// The tail is what tells the model the state of the shell, so the prompt has
	// to be in it.
	if !strings.HasSuffix(res.Output, "old output line\n") {
		t.Fatalf("first contact kept the wrong end: %q", res.Output[len(res.Output)-40:])
	}
}

func TestSendIsSerializedPerSession(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}

	// Every read after this parks until the gate opens, so the peak count is the
	// number of calls that were inside one session at the same time.
	gate := make(chan struct{})
	f.readGate = gate
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := call(t, s, "session_send", args{"session": "agent-1", "data": "x\n"}); err != nil {
				t.Errorf("send: %v", err)
			}
		}()
	}
	// The first call to reach the gate has to be released before the peak is
	// meaningful, or nothing runs at all.
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	if f.peakBlocked != 1 {
		t.Fatalf("%d calls were inside the session at once, want 1", f.peakBlocked)
	}
}

func TestInterruptSendsCtrlC(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{}); err != nil {
		t.Fatal(err)
	}
	_, _, err := call(t, s, "session_interrupt", args{"session": "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	sess := f.sessions["sess1"]
	f.mu.Unlock()
	if !strings.HasPrefix(string(sess.log), "\x03") {
		t.Fatalf("log = %q, want it to start with Ctrl-C", sess.log)
	}
}

func TestCloseForgetsTheSession(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	_, res, err := call(t, s, "session_close", args{"session": "build"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionState != "closed" {
		t.Fatalf("state = %q", res.SessionState)
	}
	// The name is free again once the session is gone.
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatalf("the name should be reusable: %v", err)
	}
}

func TestReadOnlyRegistersNoWriteTools(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.ReadOnly = true })
	names := map[string]bool{}
	for _, d := range s.definitions() {
		names[d.Name] = true
	}
	for _, want := range []string{"session_list", "session_read"} {
		if !names[want] {
			t.Fatalf("%s is missing", want)
		}
	}
	// Opening a session creates one on the target, so read-only does not offer
	// it either. A model that wants a shell needs a server that may write.
	for _, unwanted := range []string{"session_open", "session_send", "session_interrupt", "session_close"} {
		if names[unwanted] {
			t.Fatalf("%s is registered in read-only mode", unwanted)
		}
	}
	// A model that guessed the name anyway gets a protocol error, which says
	// the tool is absent rather than that the call was refused.
	_, _, err := s.dispatch(context.Background(), "session_send", args{})
	if _, isTool := ToolError(err); isTool {
		t.Fatalf("err = %v, want a protocol error for an unregistered tool", err)
	}
}

func TestSinglePeerRejectsThePeerArgument(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{"peer": "laptop"}); err == nil {
		t.Fatal("one target means nothing to choose, so peer must be refused")
	} else if !strings.Contains(err.Error(), "--allow-peer") {
		t.Fatalf("err = %v, want it to name the way out", err)
	}
}

func TestMultiPeerOffersTheChoice(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.Peers = []string{"", "laptop"} })
	found := false
	for _, d := range s.definitions() {
		_, ok := d.InputSchema["properties"].(map[string]any)["peer"]
		if ok {
			found = true
		}
	}
	if !found {
		t.Fatal("with two targets a tool must take a peer argument")
	}
	if _, _, err := call(t, s, "session_open", args{"peer": "desktop"}); err == nil {
		t.Fatal("a peer this process does not serve must be refused")
	}
}

func TestListProbesEachSession(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Sessions))
	}
	if res.Sessions[0].State != "running" {
		t.Fatalf("state = %q, want running", res.Sessions[0].State)
	}
}

func TestListReportsAProbeThatNeedsApproval(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	f.readErr = errorString("session pending approval")
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	row := res.Sessions[0]
	if row.State != "unknown" {
		t.Fatalf("state = %q, want unknown", row.State)
	}
	if !strings.Contains(row.ProbeError, "approve") {
		t.Fatalf("probe error = %q, want the approve command", row.ProbeError)
	}
}

func TestResultIsJSONDecodable(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	_, res, err := call(t, s, "session_send", args{"session": "build", "data": "echo hi\\n"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"output", "reason", "session_state", "cursor", "gap", "written"} {
		if _, ok := back[key]; !ok {
			t.Fatalf("%s is missing from %s", key, b)
		}
	}
}

func TestConcurrentOpensRespectTheSessionCap(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, func(o *Options) { o.MaxSessions = 2 })

	var wg sync.WaitGroup
	opened := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.dispatch(context.Background(), "session_open", args{"name": fmt.Sprintf("s%d", i)})
			opened[i] = err
		}(i)
	}
	wg.Wait()

	got := 0
	for _, err := range opened {
		if err == nil {
			got++
		}
	}
	// A slot is claimed before the create, so opens that arrive together cannot
	// all see room for one.
	if got != 2 {
		t.Fatalf("%d opens succeeded, want the cap of 2", got)
	}
}

func TestASendDoesNotTrimTheWayAFirstReadDoes(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := s.dispatch(context.Background(), "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	// A long run writes a lot after the session was opened, so what a send
	// returns is far more than a first contact may carry.
	f.grow("build", 40_000)

	_, res, err := s.dispatch(context.Background(), "session_send", args{"session": "build", "data": "ls\\n"})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*result)
	// The session was read once at open, so this is not a first contact and
	// nothing is dropped for size.
	if r.OmittedFrom != 0 || r.OmittedTo != 0 {
		t.Fatalf("a send dropped %d..%d of the stream", r.OmittedFrom, r.OmittedTo)
	}
}

func TestListMarksWhatThisProcessOpened(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := s.dispatch(context.Background(), "session_open", args{"name": "mine"}); err != nil {
		t.Fatal(err)
	}
	// The catalog is the only record a fresh process has, and it does not say
	// which process created what.
	f.catalogOnly("theirs")

	_, res, err := s.dispatch(context.Background(), "session_list", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := res.(*result).Sessions
	byAlias := map[string]bool{}
	for _, r := range rows {
		byAlias[r.Session] = r.OpenedByUs
	}
	if !byAlias["mine"] {
		t.Fatal("the session this process opened is not marked")
	}
	if byAlias["theirs"] {
		t.Fatal("a session found in the catalog is not opened by this process")
	}
}

func TestCancelledSendNoteNamesTheByteCountWhenTheTargetReportedIt(t *testing.T) {
	// A target that answers a cut-off write with a count lets the note be exact.
	// That is the better case, and it must not be rounded down to "unknown".
	note := cancelledSendNote(Sent{Written: 7, WrittenKnown: true}, 12)
	if !strings.Contains(note, "7 of 12") {
		t.Fatalf("note = %q, want the counts named", note)
	}
	if strings.Contains(note, "unknown") {
		t.Fatalf("note = %q, want the counts rather than a guess", note)
	}
	// Without a reply the zero is not a count, so it must not be reported as one.
	note = cancelledSendNote(Sent{Written: 0, WrittenKnown: false}, 12)
	if !strings.Contains(note, "unknown") {
		t.Fatalf("note = %q, want the count reported as unknown", note)
	}
	if strings.Contains(note, "0 of 12") {
		t.Fatalf("note = %q, a silent zero would be read as nothing was written", note)
	}
}

// pendingApproval is what a target in pre mode answers for a gated read.
func pendingApproval(id string) error {
	return errors.New("attach pending approval; ask the operator to run: tyd session approve " + id)
}

// A target in pre mode refuses every read until it is approved, and the approval
// is spent by the first read that gets through. A list that probes every session
// therefore spends the operator's approval on a probe, and the model's own send
// then needs another one. The catalog already says what the list needs to say, so
// once a target has asked for approval it is not probed again.
func TestListDoesNotSpendAnApprovalOnAProbe(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	for _, name := range []string{"a1", "b2", "c3"} {
		if _, _, err := call(t, s, "session_open", args{"name": name}); err != nil {
			t.Fatal(err)
		}
	}

	// The target gates every read, the way a pre-mode daemon does.
	f.readErrFor = func(id string) error { return pendingApproval(id) }
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 3 {
		t.Fatalf("rows = %d, want 3", len(res.Sessions))
	}
	if !strings.Contains(textOf(t, res), "approval") {
		t.Fatalf("the list must say the target wants approval:\n%s", textOf(t, res))
	}

	// The operator approves, which is one-shot. The next list is then the next
	// thing to ask the target for, and it must not be the thing that spends it.
	f.readErrFor = nil
	f.resetReads()
	_, res, err = call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.readCount(); got > 1 {
		t.Fatalf("a list of 3 rows on a target that requires approval made %d target reads; "+
			"each one can spend the operator approval", got)
	}
	for _, row := range res.Sessions {
		if row.ProbeError != "" && !strings.Contains(row.ProbeError, "approval") {
			t.Fatalf("row %s: probe error %q", row.Session, row.ProbeError)
		}
	}
}

func textOf(t *testing.T, res *result) string {
	t.Helper()
	if res == nil {
		return ""
	}
	return res.Output
}

// Once a target has let a call through, it is not gated any more, so a list goes
// back to probing it. Otherwise a daemon moved out of pre mode would leave the
// list permanently unprobed for the life of the process.
func TestAGatedTargetIsProbedAgainOnceACallGetsThrough(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	f.readErrFor = func(id string) error { return pendingApproval(id) }
	if _, _, err := call(t, s, "session_list", args{}); err != nil {
		t.Fatal(err)
	}
	if _, gated := s.needsApproval(""); !gated {
		t.Fatal("a target that asked for approval must be recorded as gated")
	}

	// The operator approves; the model's own call goes through.
	f.readErrFor = nil
	if _, _, err := call(t, s, "session_send", args{"session": "build", "data": "ls\n"}); err != nil {
		t.Fatal(err)
	}
	if _, gated := s.needsApproval(""); gated {
		t.Fatal("a call that got through must clear the gate")
	}
	f.resetReads()
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if f.readCount() == 0 {
		t.Fatal("the list must probe again once the target is open")
	}
	if res.Sessions[0].State != "running" {
		t.Fatalf("state = %q, want running from a fresh probe", res.Sessions[0].State)
	}
}

// The rows of a gated target are still listed, from the catalog. A model that
// could not see them at all would open a second session on the same machine.
func TestAGatedTargetStillListsItsRows(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	for _, name := range []string{"a1", "b2"} {
		if _, _, err := call(t, s, "session_open", args{"name": name}); err != nil {
			t.Fatal(err)
		}
	}
	f.readErrFor = func(id string) error { return pendingApproval(id) }
	_, res, err := call(t, s, "session_list", args{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 2 {
		t.Fatalf("rows = %d, want both sessions listed", len(res.Sessions))
	}
	for _, row := range res.Sessions {
		if row.ProbeError == "" {
			t.Fatalf("row %s must say why it was not probed", row.Session)
		}
		if row.Recorded == "" {
			t.Fatalf("row %s must still carry what the catalog recorded", row.Session)
		}
	}
}

// Zero is the zero value of Options, so it has to mean the default rather than no
// limit: an embedder that leaves the field unset must get the cap, and a cap
// that vanishes on a typo is worse than one that gets in the way.
func TestZeroMaxSessionsIsTheDefaultNotNoLimit(t *testing.T) {
	f := newFakeBackend()
	log := newLogger(io.Discard)
	if got := newServer(f, log, Options{}).maxSessions; got != maxSessions {
		t.Fatalf("maxSessions = %d, want the default %d", got, maxSessions)
	}
	if got := newServer(f, log, Options{MaxSessions: 0}).maxSessions; got != maxSessions {
		t.Fatalf("maxSessions = %d for an explicit zero, want the default %d", got, maxSessions)
	}
	if got := newServer(f, log, Options{MaxSessions: 3}).maxSessions; got != 3 {
		t.Fatalf("maxSessions = %d, want 3", got)
	}
	if got := newServer(f, log, Options{MaxSessions: -1}).maxSessions; got != maxSessions {
		t.Fatalf("maxSessions = %d for a negative, want the default %d", got, maxSessions)
	}
}

// The log is a record of what the tools did, not of what the terminal said. A
// send writes the operator's keystrokes and reads back whatever the command
// printed, and both of those are the kind of thing that ends up in a bug report
// or a log file. A marker is pushed through a session and the log is searched
// for it, so the invariant is checked rather than asserted in a comment.
func TestTheLogNeverCarriesTerminalContent(t *testing.T) {
	const marker = "tyd-log-canary-4f21ab"
	f := newFakeBackend()
	var logBuf strings.Builder
	s := testServerWithLog(f, &logBuf)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := call(t, s, "session_send", args{
		"session": "build", "data": "echo " + marker + "\n",
	}); err != nil {
		t.Fatal(err)
	}
	// A read that fails takes an error path of its own, and that path logs too.
	f.readErrFor = func(string) error { return errors.New("target said: " + marker) }
	if _, _, err := call(t, s, "session_list", args{}); err != nil {
		t.Fatal(err)
	}
	f.readErrFor = nil
	if _, _, err := call(t, s, "session_read", args{"session": "build"}); err != nil {
		t.Fatal(err)
	}

	got := logBuf.String()
	if got == "" {
		t.Fatal("the test proved nothing: the log is empty")
	}
	if strings.Contains(got, marker) {
		t.Fatalf("terminal content reached the log:\n%s", got)
	}
	// It is still useful: the tool, the session and the byte count are there.
	for _, want := range []string{"session_send", "session_open"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the log lost %q, which is what it is for:\n%s", want, got)
		}
	}
}
