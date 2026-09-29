package live

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
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

func TestOutputLogCursorAheadAfterAbandon(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	seen := []byte("seen-in-memory-not-on-disk")
	l.Append(seen)
	r := l.Read(0)
	if string(r.Data) != string(seen) {
		t.Fatalf("live read %q", r.Data)
	}
	oldEpoch := r.Epoch
	oldCursor := r.CursorNext
	if oldCursor == 0 || oldEpoch == 0 {
		t.Fatalf("want assigned seq, got %+v", r)
	}
	l.abandon()

	l2 := openOutputLog(dir, 64<<20)
	defer l2.Close()
	if l2.Epoch() == oldEpoch {
		t.Fatalf("unclean restart should bump epoch, still %d", oldEpoch)
	}
	ahead := l2.ReadAt(oldCursor, oldEpoch)
	if !ahead.CursorAhead || len(ahead.Data) != 0 {
		t.Fatalf("want cursor_ahead, got %+v", ahead)
	}

	fresh := bytes.Repeat([]byte("Z"), 64)
	l2.Append(fresh)
	waitFlushed(t, l2)
	stale := l2.ReadAt(oldCursor, oldEpoch)
	if !stale.CursorAhead || bytes.Contains(stale.Data, []byte("Z")) {
		t.Fatalf("stale cursor must not return new bytes: %+v %q", stale, stale.Data)
	}
	reset := l2.ReadAt(ahead.CursorNext, ahead.Epoch)
	if !bytes.Contains(reset.Data, []byte("Z")) {
		t.Fatalf("after reset want new bytes, got %q", reset.Data)
	}
}

func TestOutputLogCursorAheadOnSeqHole(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 64<<20)
	l.Append([]byte("AAA"))
	waitFlushed(t, l)
	if err := writeUintFile(filepath.Join(dir, outputSeqFile), 9); err != nil {
		t.Fatal(err)
	}
	oldEpoch := l.Epoch()
	l.abandon()

	l2 := openOutputLog(dir, 64<<20)
	defer l2.Close()
	ahead := l2.ReadAt(3, oldEpoch)
	if !ahead.CursorAhead || bytes.Contains(ahead.Data, []byte("YYY")) {
		t.Fatalf("hole should be cursor_ahead %+v %q", ahead, ahead.Data)
	}
	l2.Append([]byte("YYY"))
	waitFlushed(t, l2)
	stale := l2.ReadAt(3, oldEpoch)
	if !stale.CursorAhead || bytes.Contains(stale.Data, []byte("YYY")) {
		t.Fatalf("must not splice YYY onto the hole: %+v %q", stale, stale.Data)
	}
	start := l2.ReadAt(0, ahead.Epoch)
	if !bytes.HasPrefix(start.Data, []byte("AAA")) {
		t.Fatalf("durable prefix lost: %q", start.Data)
	}
	tail := l2.ReadAt(ahead.CursorNext, ahead.Epoch)
	if !bytes.Contains(tail.Data, []byte("YYY")) {
		t.Fatalf("new bytes at high-water %q", tail.Data)
	}
}

func TestOutputLogConcurrentReadWriteRotate(t *testing.T) {
	dir := t.TempDir()
	l := openOutputLog(dir, 8<<10)
	defer l.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := bytes.Repeat([]byte("w"), 256)
		for {
			select {
			case <-stop:
				return
			default:
				l.Append(buf)
			}
		}
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var cursor, epoch uint64
			for {
				select {
				case <-stop:
					return
				default:
					r := l.ReadAt(cursor, epoch)
					if r.Epoch != 0 {
						epoch = r.Epoch
					}
					if r.CursorAhead {
						cursor = r.CursorNext
						continue
					}
					cursor = r.CursorNext
				}
			}
		}()
	}

	deadline := time.Now().Add(3 * time.Second)
	rotated := false
	for time.Now().Before(deadline) {
		r := l.Read(0)
		if r.Dropped > 0 {
			rotated = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if !rotated {
		r := l.Read(0)
		if r.Dropped == 0 {
			t.Fatal("expected a dropped prefix from rotation")
		}
	}
}
