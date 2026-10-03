package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// toolNamed returns a registered tool, or nil. Used to inspect the schema rather than
// only the presence.
func toolNamed(s *server, name string) *toolDef {
	for _, d := range s.definitions() {
		if d.Name == name {
			t := d
			return &t
		}
	}
	return nil
}

// Acceptance 1: no --file-root means the file tools do not exist.
//
// **Absent, not refused.** A model that cannot see a tool does not try it, and cannot
// be surprised by a refusal it has to interpret — which is the same reason the
// read-only write tools are missing rather than present-and-refusing.
func TestNoFileRootMeansNoFileTools(t *testing.T) {
	s := testServer(newFakeBackend(), nil) // no FileRootConfigured
	for _, name := range []string{"file_read", "file_write"} {
		if hasTool(s, name) {
			t.Errorf("%s is registered with no file root configured", name)
		}
	}
	// And calling one by name is refused, because dispatch is reachable by name and
	// the tool list is not the only thing that decides.
	for _, name := range []string{"file_read", "file_write"} {
		_, _, err := s.dispatch(t.Context(), name, args{"session": "agent-1", "path": "a.txt"})
		if err == nil {
			t.Errorf("%s was answered with no file root configured", name)
		}
	}

	// session_open must not grow a `root` argument here either. One that silently does
	// nothing is worse than none: a model would pass it and believe it had narrowed
	// something.
	if p := toolNamed(s, "session_open"); p != nil {
		if _, ok := schemaProps(t, p.InputSchema)["root"]; ok {
			t.Error("session_open offers a root argument where there are no file tools")
		}
	}
}

// The other side of acceptance 1: with a root, they are there.
func TestAFileRootRegistersTheFileTools(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.FileRootConfigured = true })
	for _, name := range []string{"file_read", "file_write"} {
		if !hasTool(s, name) {
			t.Errorf("%s is missing with a file root configured", name)
		}
	}
	if p := toolNamed(s, "session_open"); p == nil || schemaProps(t, p.InputSchema)["root"] == nil {
		t.Error("session_open has no root argument where file tools exist")
	}
}

// Acceptance 2: --read-only stops a file write at both gates.
//
// Registration and dispatch are different gates and only one of them is a promise to
// the model. A tool that is merely absent can still be named in a request, so the
// refusal cannot live only in the tool list.
func TestReadOnlyStopsAFileWriteAtBothGates(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) {
		o.FileRootConfigured = true
		o.ReadOnly = true
	})

	// Gate one: not in the list.
	if hasTool(s, "file_write") {
		t.Error("file_write is registered in read-only mode")
	}
	// Gate two: refused by name.
	_, _, err := s.dispatch(t.Context(), "file_write", args{
		"session": "agent-1", "path": "a.txt", "mode": "create",
		"content": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil {
		t.Fatal("file_write was answered in read-only mode")
	}
	// And the refusal is the same shape as every other write tool's, so a model cannot
	// tell this one apart from session_send being absent.
	if !strings.Contains(err.Error(), "no tool named file_write") {
		t.Errorf("the refusal does not match the others: %v", err)
	}

	// Reading is still allowed: read-only means nothing is changed.
	if !hasTool(s, "file_read") {
		t.Error("file_read is missing in read-only mode; read-only changes nothing")
	}
}

// Acceptance 3: the model is told the approval is spent.
//
// A model that reads a failure as "not now" retries on its own, and the retry has no
// approval behind it — the approval was consumed before the operation ran. So the
// wording is in the tool description, which is what the model reads before it tries,
// not only in the error it gets afterwards.
func TestTheToolDescriptionSaysTheApprovalIsSpent(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.FileRootConfigured = true })
	d := toolNamed(s, "file_write")
	if d == nil {
		t.Fatal("file_write is missing")
	}
	desc := d.Description
	for _, want := range []string{"approval", "spent"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the description does not mention %q: %s", want, desc)
		}
	}
	// And it must not tell the model a plain retry will work.
	for _, forbidden := range []string{"just try again", "retry and it will"} {
		if strings.Contains(strings.ToLower(desc), forbidden) {
			t.Errorf("the description suggests a bare retry: %s", desc)
		}
	}
	// A read is an approval too, and says so.
	if rd := toolNamed(s, "file_read"); rd == nil || !strings.Contains(rd.Description, "approval") {
		t.Error("file_read does not say it needs an approval")
	}
}

// The path is passed through, not interpreted. The tool layer resolves the session and
// nothing else, so these assertions are about plumbing rather than about policy.
func TestTheFileToolsPassTheirArgumentsThrough(t *testing.T) {
	be := newFakeBackend()
	s := testServer(be, func(o *Options) { o.FileRootConfigured = true })
	st, err := s.reserve("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	s.adopt(st, Session{ID: "s1", Alias: "agent-1"})
	// The fake keeps its own session table, so it is told about this one too.
	be.mu.Lock()
	be.sessions["s1"] = &fakeSession{id: "s1", alias: "agent-1"}
	be.alias["agent-1"] = "s1"
	be.mu.Unlock()

	content := []byte("the bytes")
	if _, _, err := s.dispatch(t.Context(), "file_write", args{
		"session": "agent-1", "path": "docs/n.md", "mode": "replace",
		"content":         base64.StdEncoding.EncodeToString(content),
		"expected_sha256": strings.Repeat("a", 64),
	}); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.fileCalls) != 1 {
		t.Fatalf("recorded %d file calls, want 1", len(be.fileCalls))
	}
	c := be.fileCalls[0]
	if c.op != "write" || c.session != "s1" {
		t.Errorf("call recorded as %s on %s", c.op, c.session)
	}
	if c.write.Path != "docs/n.md" || !c.write.Replace || c.write.Create {
		t.Errorf("path or mode was altered: %+v", c.write)
	}
	if string(c.write.Content) != string(content) {
		t.Errorf("content arrived as %q", c.write.Content)
	}
	if c.write.ExpectedSHA != strings.Repeat("a", 64) {
		t.Errorf("expected_sha256 arrived as %q", c.write.ExpectedSHA)
	}
}

// A root is remembered on the session, and a call may narrow further but never back
// out to the ceiling. The agent resolves the result; this only joins two strings.
func TestARootIsRememberedOnTheSessionAndCanOnlyNarrow(t *testing.T) {
	be := newFakeBackend()
	s := testServer(be, func(o *Options) { o.FileRootConfigured = true })

	if _, _, err := s.dispatch(t.Context(), "session_open", args{"name": "agent-1", "root": "project"}); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	var got string
	found := false
	for _, sess := range be.sessions {
		if sess.root == "project" {
			got, found = sess.root, true
		}
	}
	be.mu.Unlock()
	if !found {
		t.Fatal("session_open did not record the root on the session it opened")
	}
	if got != "project" {
		t.Fatalf("session_open recorded root %q, want project", got)
	}

	// A call with no root of its own starts from the session's.
	if _, _, err := s.dispatch(t.Context(), "file_read", args{"session": "agent-1", "path": "a.txt"}); err != nil {
		t.Fatal(err)
	}
	// A call that narrows further composes rather than replaces.
	if _, _, err := s.dispatch(t.Context(), "file_read", args{
		"session": "agent-1", "path": "a.txt", "root": "sub",
	}); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	var roots []string
	for _, c := range be.fileCalls {
		roots = append(roots, c.req.Root)
	}
	if len(roots) != 2 || roots[0] != "project" || roots[1] != "project/sub" {
		t.Errorf("roots recorded as %v, want [project project/sub]", roots)
	}
}

// The arguments that do not apply are refused rather than ignored, because an ignored
// field is how a field forwarded across two hops goes missing without anyone noticing.
func TestFileToolArgumentsAreValidated(t *testing.T) {
	be := newFakeBackend()
	s := testServer(be, func(o *Options) { o.FileRootConfigured = true })
	st, err := s.reserve("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	s.adopt(st, Session{ID: "s1", Alias: "agent-1"})
	// The fake keeps its own session table, so it is told about this one too.
	be.mu.Lock()
	be.sessions["s1"] = &fakeSession{id: "s1", alias: "agent-1"}
	be.alias["agent-1"] = "s1"
	be.mu.Unlock()

	for name, a := range map[string]args{
		"no path":         {"session": "agent-1"},
		"a blank path":    {"session": "agent-1", "path": "   "},
		"no mode":         {"session": "agent-1", "path": "a.txt", "content": ""},
		"an unknown mode": {"session": "agent-1", "path": "a.txt", "mode": "clobber", "content": ""},
		"content not b64": {"session": "agent-1", "path": "a.txt", "mode": "create", "content": "not base64!"},
	} {
		_, _, err := s.dispatch(t.Context(), "file_write", a)
		if err == nil {
			t.Errorf("file_write accepted %s", name)
		}
	}
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.fileCalls) != 0 {
		t.Errorf("%d refused calls still reached the backend", len(be.fileCalls))
	}
}

// The contract test: the tool list is the API, so its shape is pinned rather than
// described. This one is about the file tools specifically.
func TestTheFileToolSchemasAreWellFormed(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) { o.FileRootConfigured = true })
	for _, name := range []string{"file_read", "file_write"} {
		d := toolNamed(s, name)
		if d == nil {
			t.Fatalf("%s is missing", name)
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var probe struct {
			Name        string         `json:"name"`
			Title       string         `json:"title"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		}
		if err := json.Unmarshal(b, &probe); err != nil {
			t.Fatal(err)
		}
		if probe.Title == "" || probe.Description == "" {
			t.Errorf("%s has an empty title or description", name)
		}
		for _, want := range []string{"session", "path"} {
			if _, ok := schemaProps(t, probe.InputSchema)[want]; !ok {
				t.Errorf("%s has no %s property", name, want)
			}
		}
		// Every property must have a description: a model reads these.
		for prop, v := range schemaProps(t, probe.InputSchema) {
			m, _ := v.(map[string]any)
			if desc, _ := m["description"].(string); strings.TrimSpace(desc) == "" {
				t.Errorf("%s.%s has no description", name, prop)
			}
		}
	}
	// file_write's mode is an enum, not a free string: "create" and "replace" are the
	// only two, and there is deliberately no mode that does both.
	d := toolNamed(s, "file_write")
	mode, _ := schemaProps(t, d.InputSchema)["mode"].(map[string]any)
	enum, _ := mode["enum"].([]string)
	if len(enum) != 2 || enum[0] != "create" || enum[1] != "replace" {
		t.Errorf("mode enum is %v, want [create replace]", enum)
	}
}

// schemaProps reaches a tool's declared properties out of its input schema, which is
// a plain map because the whole thing is the wire format.
func schemaProps(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	props, _ := input["properties"].(map[string]any)
	if props == nil {
		t.Fatalf("input schema has no properties: %v", input)
	}
	return props
}
