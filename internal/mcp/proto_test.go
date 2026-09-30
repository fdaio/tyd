package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// exchange runs a whole conversation against a server and hands back the frames
// it wrote. It is the closest a test gets to what a client sees.
type exchange struct {
	t     *testing.T
	in    *os.File
	out   *os.File
	lines chan message
	done  chan error
}

func newExchange(t *testing.T, b Backend, opts Options) *exchange {
	t.Helper()
	// Real pipes, not bytes buffers: a test has to write a frame while the
	// server is parked inside another one, and it has to read frames as the
	// server writes them.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ex := &exchange{t: t, in: inW, out: outW, lines: make(chan message, 64), done: make(chan error, 1)}

	go ex.collect(outR)
	go func() {
		err := Serve(context.Background(), inR, ex.out, b, nil, opts)
		inR.Close()
		ex.done <- err
		// Closing the input lets the collector see end of input once the server
		// has flushed its last frame.
	}()
	return ex
}

// collect turns the server's output into frames on a channel. A test reads them
// in order, so a race on the buffer itself cannot happen.
func (e *exchange) collect(r *os.File) {
	defer r.Close()
	dec := newDecoder(r)
	for {
		m, err := dec.next()
		if err != nil {
			// A frame the collector cannot read is the test client's problem, not
			// the server's, so it skips it the same way a client would.
			var bad *frameError
			if errors.As(err, &bad) {
				continue
			}
			close(e.lines)
			return
		}
		e.lines <- m
	}
}

func (e *exchange) send(t *testing.T, m any) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.in.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

func (e *exchange) writeRaw(s string) {
	if _, err := e.in.Write([]byte(s)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *exchange) request(t *testing.T, id int, method string, params any) message {
	t.Helper()
	e.send(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return e.replyTo(t, id)
}

// replyTo waits for the answer to one id. A frame for another id is left in the
// order it arrived, because a server that answers a bad frame puts an error with
// a null id into the stream.
func (e *exchange) replyTo(t *testing.T, id int) message {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		m := e.next(t, deadline)
		var got float64
		if err := json.Unmarshal(m.ID, &got); err != nil {
			// A null id marks a complaint about a frame this test could not
			// write, so there is nothing to match against.
			continue
		}
		if int(got) == id {
			return m
		}
	}
}

// next returns the next frame, skipping progress notifications.
func (e *exchange) next(t *testing.T, deadline <-chan time.Time) message {
	t.Helper()
	for {
		select {
		case m, ok := <-e.lines:
			if !ok {
				t.Fatal("the server stopped serving")
			}
			if m.Method == "notifications/progress" {
				continue
			}
			return m
		case <-deadline:
			t.Fatal("no frame arrived")
			return message{}
		}
	}
}

func (e *exchange) close(t *testing.T) {
	t.Helper()
	e.in.Close()
	select {
	case err := <-e.done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return when its input ended")
	}
}

func TestInitializeNegotiatesTheVersion(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)

	rep := ex.request(t, 1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"clientInfo":      map[string]any{"name": "test", "version": "1"},
	})
	if rep.Error != nil {
		t.Fatalf("error: %v", rep.Error)
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools map[string]any `json:"tools"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(rep.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != "2025-06-18" {
		t.Fatalf("version = %q", res.ProtocolVersion)
	}
	if res.ServerInfo.Name != "tyd" {
		t.Fatalf("serverInfo = %+v", res.ServerInfo)
	}
	if res.Capabilities.Tools == nil {
		t.Fatal("the tools capability must be declared")
	}
}

func TestInitializeAnswersAnUnknownVersion(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)

	rep := ex.request(t, 1, "initialize", map[string]any{"protocolVersion": "1999-01-01"})
	if rep.Error != nil {
		t.Fatalf("error: %v", rep.Error)
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	json.Unmarshal(rep.Result, &res)
	if res.ProtocolVersion != protocolVersion {
		t.Fatalf("version = %q, want the newest this server speaks", res.ProtocolVersion)
	}
}

func TestPing(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)
	rep := ex.request(t, 1, "ping", map[string]any{})
	if rep.Error != nil {
		t.Fatalf("error: %v", rep.Error)
	}
	if string(rep.Result) != "{}" {
		t.Fatalf("result = %s", rep.Result)
	}
}

func TestUnknownMethodIsAProtocolError(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)
	rep := ex.request(t, 1, "resources/list", map[string]any{})
	if rep.Error == nil || rep.Error.Code != codeMethodNotFound {
		t.Fatalf("error = %+v, want method not found", rep.Error)
	}
}

func TestToolsListCarriesSchemas(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)
	rep := ex.request(t, 1, "tools/list", map[string]any{})
	var res struct {
		Tools []toolDef `json:"tools"`
	}
	if err := json.Unmarshal(rep.Result, &res); err != nil {
		t.Fatal(err)
	}
	byName := map[string]toolDef{}
	for _, d := range res.Tools {
		byName[d.Name] = d
	}
	for _, want := range []string{"session_open", "session_list", "session_send", "session_read", "session_interrupt", "session_close"} {
		d, ok := byName[want]
		if !ok {
			t.Fatalf("%s is missing", want)
		}
		if d.Description == "" {
			t.Fatalf("%s has no description: a model picks a tool by its description", want)
		}
		if d.InputSchema["type"] != "object" {
			t.Fatalf("%s schema = %+v", want, d.InputSchema)
		}
	}
	if byName["session_read"].Annotations == nil || !byName["session_read"].Annotations.ReadOnlyHint {
		t.Fatal("session_read must be marked read-only")
	}
	if byName["session_send"].Annotations == nil || !byName["session_send"].Annotations.DestructiveHint {
		t.Fatal("session_send must be marked destructive")
	}
}

func TestToolsCallReturnsTextAndStructuredContent(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)

	rep := ex.request(t, 1, "tools/call", map[string]any{
		"name":      "session_open",
		"arguments": map[string]any{"name": "build"},
	})
	if rep.Error != nil {
		t.Fatalf("error: %v", rep.Error)
	}
	var res toolResult
	if err := json.Unmarshal(rep.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("content = %+v", res.Content)
	}
	if !strings.Contains(res.Content[0].Text, "tyd session attach build") {
		t.Fatalf("text = %q", res.Content[0].Text)
	}
	if res.IsError {
		t.Fatal("a successful call must not set isError")
	}
	// A client that predates structuredContent still needs the fields, so the
	// text carries the same footer a model reads.
	if !strings.Contains(res.Content[0].Text, "[tyd:") {
		t.Fatalf("text = %q", res.Content[0].Text)
	}
}

func TestToolFailureIsAResultNotAnError(t *testing.T) {
	f := newFakeBackend()
	f.sendErr = errorString("session in use: attached elsewhere")
	ex := newExchange(t, f, Options{})
	defer ex.close(t)

	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})
	rep := ex.request(t, 2, "tools/call", map[string]any{
		"name":      "session_send",
		"arguments": map[string]any{"session": "build", "data": "ls\\n"},
	})
	if rep.Error != nil {
		t.Fatalf("a refused call is not a protocol error: %v", rep.Error)
	}
	var res toolResult
	json.Unmarshal(rep.Result, &res)
	if !res.IsError {
		t.Fatal("a refused call must set isError")
	}
	if !strings.Contains(res.Content[0].Text, "detach") {
		t.Fatalf("text = %q, want the way out named", res.Content[0].Text)
	}
}

func TestUnknownToolIsAProtocolError(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)
	rep := ex.request(t, 1, "tools/call", map[string]any{"name": "session_exec", "arguments": map[string]any{}})
	if rep.Error == nil || rep.Error.Code != codeMethodNotFound {
		t.Fatalf("error = %+v, want method not found", rep.Error)
	}
}

func TestBadArgumentTypeIsInvalidParams(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)
	rep := ex.request(t, 1, "tools/call", map[string]any{
		"name":      "session_open",
		"arguments": map[string]any{"name": 42},
	})
	if rep.Error == nil || rep.Error.Code != codeInvalidParams {
		t.Fatalf("error = %+v, want invalid params", rep.Error)
	}
	if !strings.Contains(rep.Error.Message, "must be a string") {
		t.Fatalf("message = %q", rep.Error.Message)
	}
}

func TestProgressIsReportedWhileAReadIsParked(t *testing.T) {
	f := newFakeBackend()
	// The interval is what the test waits for, so shrink it rather than sleeping
	// for five seconds.
	saved := progressInterval
	progressInterval = 10 * time.Millisecond
	defer func() { progressInterval = saved }()

	ex := newExchange(t, f, Options{})
	defer ex.close(t)

	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})

	gate := f.parkReads()
	defer close(gate)
	ex.send(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": "session_read",
		"arguments": map[string]any{
			"session": "build",
			"wait":    map[string]any{"idle_ms": float64(30_000), "wait_ms": float64(30_000)},
		},
		"_meta": map[string]any{"progressToken": "tok-1"},
	}})

	deadline := time.After(5 * time.Second)
	var reports []message
	for len(reports) == 0 {
		select {
		case m, ok := <-ex.lines:
			if !ok {
				t.Fatal("the server stopped serving")
			}
			if m.Method == "notifications/progress" {
				reports = append(reports, m)
			}
		case <-deadline:
			t.Fatal("a parked read must report progress while the client asked for it")
		}
	}
	var params struct {
		ProgressToken string `json:"progressToken"`
		Message       string `json:"message"`
	}
	if err := json.Unmarshal(reports[0].Params, &params); err != nil {
		t.Fatal(err)
	}
	if params.ProgressToken != "tok-1" {
		t.Fatalf("token = %q, want the client's own token echoed", params.ProgressToken)
	}
}

func TestCancelEndsAParkedRead(t *testing.T) {
	f := newFakeBackend()
	ex := newExchange(t, f, Options{})
	defer ex.close(t)

	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})

	f.parkReads()
	defer f.unparkReads()
	ex.send(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name":      "session_read",
		"arguments": map[string]any{"session": "build", "wait": map[string]any{"wait_ms": float64(30_000)}},
	}})

	// Wait until the read is parked, so the cancellation lands on a live call.
	deadline := time.After(5 * time.Second)
	for {
		f.mu.Lock()
		blocked := f.blocked
		f.mu.Unlock()
		if blocked > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the read never parked")
		default:
		}
		time.Sleep(time.Millisecond)
	}

	ex.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": 2, "reason": "the model changed its mind"}})

	rep := ex.replyTo(t, 2)
	if rep.Error == nil || rep.Error.Code != codeCancelled {
		t.Fatalf("a cancelled call answers with code %d, got %s", codeCancelled, string(rep.Result))
	}
	// The session lock has to be free, or every later call on it is stuck.
	f.unparkReads()
	done := make(chan struct{})
	go func() {
		ex.request(t, 3, "tools/call", map[string]any{
			"name":      "session_read",
			"arguments": map[string]any{"session": "build"},
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the per-session lock was not released after a cancellation")
	}
}

func TestMalformedFrameDoesNotKillTheConnection(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)

	ex.writeRaw("{not json\n")
	// The server owes an error for the bad frame and must still answer the ping.
	rep := ex.request(t, 1, "ping", map[string]any{})
	if rep.Error != nil {
		t.Fatalf("the server stopped serving: %v", rep.Error)
	}
	if string(rep.Result) != "{}" {
		t.Fatalf("result = %s", rep.Result)
	}
}

func TestPipelinedFramesAreAllAnswered(t *testing.T) {
	ex := newExchange(t, newFakeBackend(), Options{})
	defer ex.close(t)

	for i := 1; i <= 3; i++ {
		ex.send(t, map[string]any{"jsonrpc": "2.0", "id": i, "method": "ping", "params": map[string]any{}})
	}
	seen := map[float64]bool{}
	deadline := time.After(5 * time.Second)
	for i := 0; i < 3; i++ {
		m := ex.next(t, deadline)
		var id float64
		if err := json.Unmarshal(m.ID, &id); err != nil {
			t.Fatal(err)
		}
		seen[id] = true
	}
	if len(seen) != 3 {
		t.Fatalf("ids = %v, want all three answered", seen)
	}
}

func TestCloseOnExitEndsWhatThisProcessOpened(t *testing.T) {
	f := newFakeBackend()
	ex := newExchange(t, f, Options{CloseOnExit: true})
	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})
	ex.close(t)

	f.mu.Lock()
	calls := append([]string(nil), f.calls...)
	f.mu.Unlock()
	closed := false
	for _, c := range calls {
		if strings.HasPrefix(c, "close ") {
			closed = true
		}
	}
	if !closed {
		t.Fatalf("calls = %v, want the opened session closed on exit", calls)
	}
}

func TestSessionsSurviveByDefault(t *testing.T) {
	f := newFakeBackend()
	ex := newExchange(t, f, Options{})
	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})
	ex.close(t)

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, "close ") {
			t.Fatalf("calls = %v, want the session left alone", f.calls)
		}
	}
}

// concurrentRequests keeps the race detector honest about the per-session lock.
func TestConcurrentCallsOnOneSessionStayInOrder(t *testing.T) {
	f := newFakeBackend()
	s := testServer(f, nil)
	if _, _, err := call(t, s, "session_open", args{"name": "build"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := call(t, s, "session_read", args{"session": "build"}); err != nil {
				t.Errorf("read %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

// schemaOf pulls one tool out of the list so a test can check its shape.
func schemaOf(t *testing.T, s *server, name string) map[string]any {
	t.Helper()
	for _, d := range s.definitions() {
		if d.Name == name {
			return d.InputSchema
		}
	}
	t.Fatalf("no tool named %s", name)
	return nil
}

func requiredOf(t *testing.T, schema map[string]any) []string {
	t.Helper()
	raw, _ := schema["required"].([]string)
	return raw
}

func propertiesOf(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no properties object: %+v", schema)
	}
	return props
}

func TestSchemaAsksForNothingButWhatTheToolNeeds(t *testing.T) {
	s := testServer(newFakeBackend(), nil)

	// A model that is told an argument is required has to invent one, so only
	// the arguments a call cannot do without may be listed.
	want := map[string][]string{
		"session_open":      {},
		"session_list":      {},
		"session_send":      {"session", "data"},
		"session_read":      {"session"},
		"session_interrupt": {"session"},
		"session_close":     {"session"},
	}
	for name, expected := range want {
		got := requiredOf(t, schemaOf(t, s, name))
		if len(got) != len(expected) {
			t.Fatalf("%s requires %v, want %v", name, got, expected)
		}
		for i := range expected {
			if got[i] != expected[i] {
				t.Fatalf("%s requires %v, want %v", name, got, expected)
			}
		}
	}
}

func TestEveryToolThatWorksOnASessionNamesIt(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	for _, name := range []string{"session_send", "session_read", "session_interrupt", "session_close"} {
		props := propertiesOf(t, schemaOf(t, s, name))
		if _, ok := props["session"]; !ok {
			t.Fatalf("%s has no session property: %+v", name, props)
		}
	}
	// A tool that names no session has no business asking for one.
	props := propertiesOf(t, schemaOf(t, s, "session_open"))
	if _, ok := props["session"]; ok {
		t.Fatal("session_open takes no session argument")
	}
}

func TestReadAcceptsAMatch(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	wait, ok := propertiesOf(t, schemaOf(t, s, "session_read"))["wait"].(map[string]any)
	if !ok {
		t.Fatal("session_read has no wait object")
	}
	props, _ := wait["properties"].(map[string]any)
	if _, ok := props["match"]; !ok {
		t.Fatalf("session_read cannot wait for a pattern: %+v", props)
	}
}

func TestReadOnlyOffersNoPeerChoiceOnList(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.Peers = []string{"", "laptop"} })
	// session_list reports every target, so a peer argument would do nothing.
	if _, ok := propertiesOf(t, schemaOf(t, s, "session_list"))["peer"]; ok {
		t.Fatal("session_list must not offer a peer it cannot use")
	}
	// The tools that do take one still offer it, or the model cannot reach the
	// second machine.
	for _, name := range []string{"session_open", "session_read"} {
		props := propertiesOf(t, schemaOf(t, s, name))
		peer, ok := props["peer"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no peer property", name)
		}
		if desc, _ := peer["description"].(string); !strings.Contains(desc, "laptop") {
			t.Fatalf("%s peer description = %q, want the second target named", name, desc)
		}
	}
}

func TestServeDoesNotReturnWhileACallIsStillRunning(t *testing.T) {
	f := newFakeBackend()
	ex := newExchange(t, f, Options{CloseOnExit: true})
	ex.request(t, 1, "tools/call", map[string]any{"name": "session_open", "arguments": map[string]any{"name": "build"}})

	gate := f.parkReads()
	ex.send(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name":      "session_read",
		"arguments": map[string]any{"session": "build", "wait": map[string]any{"wait_ms": float64(30_000)}},
	}})
	// The read has to be parked before the input ends, or the test proves
	// nothing about a call that is still in flight.
	waitForBlocked(t, f)

	// Ending the input cancels the parked read. Serve waits for the answer it
	// writes, so the session is not closed underneath a running call.
	go ex.in.Close()
	select {
	case <-ex.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve returned without waiting for the call it still had")
	}
	close(gate)

	f.mu.Lock()
	calls := append([]string(nil), f.calls...)
	f.mu.Unlock()
	var closedBeforeAnswer bool
	for _, c := range calls {
		if strings.HasPrefix(c, "close ") {
			closedBeforeAnswer = true
		}
	}
	if !closedBeforeAnswer {
		t.Fatalf("calls = %v, want the session closed after the call settled", calls)
	}
}

func waitForBlocked(t *testing.T, f *fakeBackend) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		f.mu.Lock()
		blocked := f.blocked
		f.mu.Unlock()
		if blocked > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the read never parked")
		default:
		}
		time.Sleep(time.Millisecond)
	}
}
