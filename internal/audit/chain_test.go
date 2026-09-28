package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func chained(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		f.Log(Event{
			Kind:      KindAttach,
			SessionID: "session-" + string(rune('a'+i)),
			Principal: "amy",
			Time:      time.Unix(int64(1700000000+i), 0).UTC(),
		})
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChainedLogVerifies(t *testing.T) {
	path := chained(t, 4)
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a freshly written chain did not verify: line %d %s", res.BrokenAt, res.Reason)
	}
	if res.Records != 4 {
		t.Errorf("checked %d records, want 4", res.Records)
	}
}

// The point of the chain: a line edited in place is detectable, and the report
// says which line stopped making sense.
func TestVerifyDetectsAnEditedRecord(t *testing.T) {
	path := chained(t, 5)
	rewrite(t, path, 3, func(rec chainRecord) chainRecord {
		// Same shape, different content: a laundered action.
		rec.Event.Principal = "not-amy"
		return rec
	})

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an edited record verified")
	}
	if res.BrokenAt != 3 {
		t.Errorf("break reported at line %d, want 3", res.BrokenAt)
	}
	if !strings.Contains(res.Reason, "do not match its hash") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// Deleting a record from the middle breaks the link the next one points at.
func TestVerifyDetectsARemovedRecord(t *testing.T) {
	path := chained(t, 5)
	lines := readLines(t, path)
	kept := append(append([]string{}, lines[:2]...), lines[3:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a removed record went unnoticed")
	}
	if res.BrokenAt != 3 {
		t.Errorf("break reported at line %d, want 3", res.BrokenAt)
	}
	if !strings.Contains(res.Reason, "does not follow") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// A record appended after the fact cannot join the chain either, because it does
// not follow the last one.
func TestVerifyDetectsAnAppendedRecord(t *testing.T) {
	path := chained(t, 3)
	// Appended by something that is not the program, starting its own chain --
	// the way a rebuilt or spliced log looks.
	forged := encode(t, chainRecord{
		Event: Event{Kind: KindDenied, SessionID: "invented", Time: time.Unix(1800000000, 0).UTC()},
		Prev:  chainStart,
		Hash:  strings.Repeat("f", 64),
	})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(forged + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an appended record went unnoticed")
	}
}

// Truncating the tail and continuing is what a restart does; Verify must not
// complain about a chain this program wrote.
func TestChainedLogContinuesAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	for i := 0; i < 3; i++ {
		f, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f.Log(Event{Kind: KindCreate, SessionID: "s", Time: time.Unix(int64(1700000000+i), 0).UTC()})
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a chain continued across restarts did not verify: line %d %s", res.BrokenAt, res.Reason)
	}
	if res.Records != 3 {
		t.Errorf("checked %d records, want 3", res.Records)
	}
}

// An existing log written before chaining existed cannot be verified, and saying
// so is more useful than pretending it is fine.
func TestVerifyReportsAnUnchainedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	line := `{"time":"2026-09-15T12:00:00Z","event":"create","session_id":"s1"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an unchained log reported itself verified")
	}
	if !strings.Contains(res.Reason, "older tyd") {
		t.Errorf("reason = %q", res.Reason)
	}
}

// The limit of a local chain, stated as a test so it stays true: dropping the
// whole file and starting over produces a log that verifies. Only a copy the
// daemon user cannot reach catches that, and docs/security.md says so.
func TestVerifyCannotSeeAWholeFileReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Log(Event{Kind: KindClose, SessionID: "only-this", Time: time.Unix(1700000000, 0).UTC()})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatal("a rebuilt chain should verify; that is the documented limit")
	}
}

func TestVerifyOnMissingAndEmptyLogs(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.log")); !os.IsNotExist(err) {
		t.Errorf("missing log error = %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(empty)
	if err != nil {
		t.Fatal(err)
	}
	// An empty log is not a tampering finding; it just has nothing to check.
	if !res.OK() || !strings.Contains(res.Reason, "empty") {
		t.Errorf("empty log: ok=%v reason=%q", res.OK(), res.Reason)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func rewrite(t *testing.T, path string, line int, f func(chainRecord) chainRecord) {
	t.Helper()
	lines := readLines(t, path)
	rec := decode(t, lines[line-1])
	lines[line-1] = encode(t, f(rec))
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func decode(t *testing.T, line string) chainRecord {
	t.Helper()
	var rec chainRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func encode(t *testing.T, rec chainRecord) string {
	t.Helper()
	b, err := rec.encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
