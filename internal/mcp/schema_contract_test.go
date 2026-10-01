package mcp

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The tests in this file hold the contract between the tool schemas and the
// handlers behind them. A model reads the schema and nothing else, so a property
// a handler reads but the schema omits is a property the model cannot set, and a
// property the schema offers but the handler ignores is a promise the server
// does not keep.

// toolProperties is what each handler actually reads, and what each schema
// offers. The two columns are compared against each other and against the code
// below, so a property added to one side and not the other fails here.
var toolProperties = map[string]struct {
	schema   []string
	handled  []string
	required []string
}{
	"session_open": {
		schema:   []string{"name", "shell", "peer"},
		handled:  []string{"name", "shell", "peer"},
		required: nil,
	},
	"session_list": {
		schema:   nil,
		handled:  nil,
		required: nil,
	},
	"session_send": {
		schema:   []string{"session", "data", "escapes", "secret", "wait", "peer"},
		handled:  []string{"session", "data", "escapes", "secret", "wait", "peer"},
		required: []string{"session", "data"},
	},
	"session_read": {
		schema:   []string{"session", "cursor", "max_bytes", "wait", "peer"},
		handled:  []string{"session", "cursor", "max_bytes", "wait", "peer"},
		required: []string{"session"},
	},
	"session_interrupt": {
		schema:   []string{"session", "peer"},
		handled:  []string{"session", "peer"},
		required: []string{"session"},
	},
	"session_close": {
		schema:   []string{"session", "peer"},
		handled:  []string{"session", "peer"},
		required: []string{"session"},
	},
	// The nested shapes a model fills in. These are compared the same way.
	"session_send.wait": {
		schema:   []string{"idle_ms", "max_bytes", "wait_ms", "match"},
		handled:  []string{"idle_ms", "max_bytes", "wait_ms", "match"},
		required: nil,
	},
	"session_read.wait": {
		schema:   []string{"idle_ms", "max_bytes", "wait_ms", "match"},
		handled:  []string{"idle_ms", "max_bytes", "wait_ms", "match"},
		required: nil,
	},
}

func TestSchemaAndHandlerAgreeOnProperties(t *testing.T) {
	s := testServer(newFakeBackend(), func(o *Options) {
		o.Peers = []string{"", "laptop"}
	})
	for _, d := range s.definitions() {
		want, ok := toolProperties[d.Name]
		if !ok {
			t.Errorf("%s is not in the contract table; add it", d.Name)
			continue
		}
		got := propertyNames(t, d.InputSchema)
		assertSameSet(t, d.Name, got, want.schema, "schema")
		if !sameSet(requiredOf(t, d.InputSchema), want.required) {
			t.Errorf("%s requires %v, want %v", d.Name, requiredOf(t, d.InputSchema), want.required)
		}
		// Every required name has to be a real property, or the schema asks for
		// something it does not define.
		for _, r := range want.required {
			if !contains(got, r) {
				t.Errorf("%s requires %q, which its schema does not define", d.Name, r)
			}
		}
		// A property the schema offers but the handler ignores is a promise the
		// server does not keep. This is what session_list's peer argument was.
		for _, h := range want.handled {
			if !contains(got, h) {
				t.Errorf("%s reads %q, so its schema must offer it", d.Name, h)
			}
		}
		for _, p := range got {
			if !contains(want.handled, p) {
				t.Errorf("%s offers %q in its schema but the handler ignores it", d.Name, p)
			}
		}
	}
	// Nothing may be registered that the table does not know about.
	for name := range toolProperties {
		if !strings.Contains(name, ".") && !hasTool(s, name) {
			t.Errorf("%s is in the contract table but is not registered", name)
		}
	}
}

func TestWaitShapesAgreeOnProperties(t *testing.T) {
	s := testServer(newFakeBackend(), nil)
	for _, d := range s.definitions() {
		key := d.Name + ".wait"
		want, ok := toolProperties[key]
		if !ok {
			continue
		}
		wait, ok := propertiesOf(t, d.InputSchema)["wait"].(map[string]any)
		if !ok {
			t.Errorf("%s has no wait object", d.Name)
			continue
		}
		props, _ := wait["properties"].(map[string]any)
		got := keysOf(props)
		assertSameSet(t, key, got, want.schema, "schema")
		for _, h := range want.handled {
			if !contains(got, h) {
				t.Errorf("%s reads %q, so its schema must offer it", key, h)
			}
		}
		for _, p := range got {
			if !contains(want.handled, p) {
				t.Errorf("%s offers %q but the handler ignores it", key, p)
			}
		}
	}
}

// TestPeerReachesTheBackend checks the peer property mechanically, by watching
// what the backend is asked for. A schema that offers a peer the handler drops
// on the floor cannot be caught by comparing property names alone.
func TestPeerReachesTheBackend(t *testing.T) {
	var seen []string
	f := newFakeBackend()
	f.peerSeen = func(peer string) { seen = append(seen, peer) }
	s := testServer(f, func(o *Options) { o.Peers = []string{"", "laptop"} })
	if _, _, err := s.dispatch(context.Background(), "session_open", args{"name": "b"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.dispatch(context.Background(), "session_read",
		args{"session": "b", "peer": "laptop"}); err != nil {
		t.Fatal(err)
	}
	if !contains(seen, "laptop") {
		t.Fatalf("the backend saw %v, want the peer the schema offers", seen)
	}
}

func TestSessionListTakesNoPeer(t *testing.T) {
	// session_list reports every target, so a peer argument would be read and
	// then ignored. The schema must not offer one, and passing one is refused
	// rather than silently swallowed.
	s := testServer(newFakeBackend(), func(o *Options) { o.Peers = []string{"", "laptop"} })
	for _, d := range s.definitions() {
		if d.Name == "session_list" {
			if _, ok := propertiesOf(t, d.InputSchema)["peer"]; ok {
				t.Fatal("session_list must not offer a peer it cannot use")
			}
		}
	}
}

// TestToolsListJSONIsStable is a snapshot. A change here is a change to what a
// model is told, which deserves a look even when every other test still passes.
func TestToolsListJSONIsStable(t *testing.T) {
	// Relative to this package, which is where go test runs the binary.
	const snapshot = "testdata/tools_list.json"
	s := testServer(newFakeBackend(), func(o *Options) {
		o.Peers = []string{"", "laptop"}
	})
	b, err := json.MarshalIndent(s.definitions(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')

	if *update {
		if err := os.MkdirAll(filepath.Dir(snapshot), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(snapshot, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", snapshot)
		return
	}

	want, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("%v; run go test ./internal/mcp -run ToolsListJSON -update", err)
	}
	if string(b) != string(want) {
		t.Errorf("the tool list changed.\n--- got ---\n%s\n--- want ---\n%s\n"+
			"If the change is intended, run go test ./internal/mcp -run ToolsListJSON -update",
			b, want)
	}
}

var update = flag.Bool("update", false, "rewrite the tool list snapshot")

func propertyNames(t *testing.T, schema map[string]any) []string {
	t.Helper()
	return keysOf(propertiesOf(t, schema))
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasTool(s *server, name string) bool {
	for _, d := range s.definitions() {
		if d.Name == name {
			return true
		}
	}
	return false
}

func assertSameSet(t *testing.T, what string, got, want []string, side string) {
	t.Helper()
	if sameSet(got, want) {
		return
	}
	t.Errorf("%s %s offers %v, want %v", what, side, sorted(got), sorted(want))
}

// sameSet compares two lists without caring about order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
