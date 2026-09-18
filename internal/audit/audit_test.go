package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFileWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.log")
	a, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Log(Event{Kind: KindCreate, SessionID: "s1", Principal: "amy"})
	a.Log(Event{Kind: KindClose, SessionID: "s1", Time: time.Unix(0, 0)})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines=%d: %q", len(lines), b)
	}
	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first.Kind != KindCreate || first.SessionID != "s1" || first.Principal != "amy" {
		t.Fatalf("%+v", first)
	}
	if first.Time.IsZero() {
		t.Fatal("missing timestamp")
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm=%o", perm)
	}
}

func TestFileAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	for i := 0; i < 2; i++ {
		a, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		a.Log(Event{Kind: KindAttach, SessionID: "s"})
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "\n"); got != 2 {
		t.Fatalf("lines=%d", got)
	}
}

// An audit record must never be able to carry terminal or environment content.
func TestEventCarriesNoTerminalContent(t *testing.T) {
	forbidden := []string{"data", "output", "input", "env", "ring", "snapshot"}
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		name := strings.ToLower(et.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("Event.%s may leak terminal content", et.Field(i).Name)
			}
		}
		if k := et.Field(i).Type.Kind(); k == reflect.Slice || k == reflect.Map {
			t.Errorf("Event.%s is a %s; keep audit records flat metadata", et.Field(i).Name, k)
		}
	}
}
