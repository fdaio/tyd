package live

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitFlushed(t *testing.T, l *outputLog) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		n := len(l.pending)
		d := l.degraded
		l.mu.Unlock()
		if n == 0 || d {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending not flushed")
}

func TestOutputLogResumeAndPage(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	defer l.Close()

	payload := bytes.Repeat([]byte("x"), 70<<10)
	l.Append(payload)

	r1 := l.Read(0)
	if len(r1.Data) != ReadMax {
		t.Fatalf("page size %d, want %d", len(r1.Data), ReadMax)
	}
	if r1.AtEnd || r1.Dropped != 0 || r1.CursorNext != uint64(ReadMax) {
		t.Fatalf("first page %+v", r1)
	}
	r2 := l.Read(r1.CursorNext)
	if !r2.AtEnd || r2.Dropped != 0 {
		t.Fatalf("second page %+v", r2)
	}
	got := append(append([]byte(nil), r1.Data...), r2.Data...)
	if !bytes.Equal(got, payload) {
		t.Fatalf("resume lost or duplicated bytes: got %d want %d", len(got), len(payload))
	}

	idle := l.Read(r2.CursorNext)
	if len(idle.Data) != 0 || !idle.AtEnd || idle.CursorNext != r2.CursorNext {
		t.Fatalf("idle read %+v", idle)
	}
}

func TestOutputLogDroppedPrefix(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<10)
	defer l.Close()

	l.Append(bytes.Repeat([]byte("a"), 80<<10))
	waitFlushed(t, l)

	r := l.Read(0)
	if r.Dropped == 0 {
		t.Fatal("truncated prefix should set dropped")
	}
	if r.CursorNext <= r.Dropped {
		t.Fatalf("cursor_next %d should be past dropped %d", r.CursorNext, r.Dropped)
	}
	again := l.Read(r.Dropped)
	if again.Dropped != 0 {
		t.Fatalf("read from earliest still dropped=%d", again.Dropped)
	}
}

func TestOutputLogPersistsSeqAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	l.Append([]byte("abc"))
	waitFlushed(t, l)
	l.Close()

	l2 := openOutputLog(dir, 64<<20)
	defer l2.Close()
	r := l2.Read(0)
	if string(r.Data) != "abc" {
		t.Fatalf("reopen data %q", r.Data)
	}
	l2.Append([]byte("def"))
	r2 := l2.Read(3)
	if string(r2.Data) != "def" || !r2.AtEnd {
		t.Fatalf("continued seq %+v %q", r2, r2.Data)
	}
	if r2.CursorNext != 6 {
		t.Fatalf("cursor_next=%d", r2.CursorNext)
	}
}

func TestOutputLogMode0600(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	defer l.Close()
	l.Append([]byte("secret"))
	waitFlushed(t, l)

	matches, err := filepath.Glob(filepath.Join(dir, "output.[0-9]*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no output segment")
	}
	for _, p := range matches {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", p, info.Mode().Perm())
		}
	}
}

func TestOutputLogDegradeKeepsTail(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	defer l.Close()
	l.writeAll = func(*os.File, []byte) (int, error) {
		return 0, errors.New("no space left on device")
	}
	l.Append([]byte("still-readable"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !l.Degraded() {
		time.Sleep(10 * time.Millisecond)
	}
	if !l.Degraded() {
		t.Fatal("want degraded")
	}
	b, err := os.ReadFile(OutputErrPath(dir))
	if err != nil || !bytes.Contains(b, []byte("no space")) {
		t.Fatalf("output.err = %q err=%v", b, err)
	}
	r := l.Read(0)
	if !bytes.Contains(r.Data, []byte("still-readable")) {
		t.Fatalf("tail lost after degrade: %q", r.Data)
	}
	l.Append([]byte("-and-more"))
	r2 := l.Read(0)
	if !bytes.Contains(r2.Data, []byte("still-readable-and-more")) {
		t.Fatalf("ring tail after degrade: %q", r2.Data)
	}
}

func TestOutputLogCloseRemovesNeedForFiles(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	l.Append([]byte("bye"))
	waitFlushed(t, l)
	l.Close()
	RemoveDir(dir)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir still there: %v", err)
	}
}
