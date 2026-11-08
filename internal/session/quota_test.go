package session

import (
	"testing"
	"time"
)

func TestCountAndOlderThan(t *testing.T) {
	m := NewManager()
	now := time.Now().UTC()
	m.sessions["a"] = &Session{ID: "a", Owner: "alice", CreatedAt: now.Add(-2 * time.Hour)}
	m.sessions["b"] = &Session{ID: "b", Owner: "alice", CreatedAt: now.Add(-time.Hour)}
	m.sessions["c"] = &Session{ID: "c", Owner: "bob", CreatedAt: now.Add(-time.Minute)}

	if got := m.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
	if got := m.CountByOwner("alice"); got != 2 {
		t.Errorf("CountByOwner(alice) = %d, want 2", got)
	}
	if got := m.CountByOwner("nobody"); got != 0 {
		t.Errorf("CountByOwner(nobody) = %d, want 0", got)
	}
	got := m.OlderThan(90*time.Minute, now)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("OlderThan = %v, want [a]", got)
	}
	if got := m.OlderThan(0, now); got != nil {
		t.Errorf("OlderThan(0) = %v, want nil", got)
	}
}
