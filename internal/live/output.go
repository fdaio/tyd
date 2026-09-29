package live

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultOutputLogMax is the per-session disk cap. A flag on tyd up
	// can raise or lower it.
	DefaultOutputLogMax int64 = 64 << 20
	outputSegmentSize   int64 = 4 << 20
	outputMaxSegments         = 16
	// ReadMax is the server cap for one read reply. The client pages with
	// cursor_next. 64MB must not fit in a single frame.
	ReadMax = 64 << 10
	// outputTailMax keeps the last bytes after a disk failure so read can
	// still serve the ring-sized window.
	outputTailMax    = 64 << 10
	outputFlushEvery = 100 * time.Millisecond
	outputSegPrefix  = "output."
	outputErrFile    = "output.err"
)

// ReadResult is one non-blocking pull from the sequenced output log.
type ReadResult struct {
	Data       []byte
	CursorNext uint64
	Dropped    uint64
	AtEnd      bool
}

type outputSeg struct {
	start uint64
	size  int64
	path  string
}

// outputLog assigns a monotonic byte seq and writes segments on disk.
//
// Seq starts at 0 for the session and continues across agent restarts by
// reading the files already in the session dir. The PTY path never waits
// on a disk write: Append copies into memory and a loop flushes later.
// A write error sets degraded; later output stays in the tail only.
type outputLog struct {
	dir      string
	maxBytes int64
	segSize  int64

	mu        sync.Mutex
	earliest  uint64
	nextSeq   uint64
	diskEnd   uint64
	pending   []byte
	tail      []byte
	tailStart uint64
	segs      []outputSeg
	cur       *os.File
	curSize   int64
	totalSize int64
	degraded  bool
	closed    bool

	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	writeAll func(f *os.File, p []byte) (int, error)
}

func outputLayout(maxBytes int64) (segSize int64) {
	if maxBytes <= 0 {
		maxBytes = DefaultOutputLogMax
	}
	if maxBytes >= outputSegmentSize {
		return outputSegmentSize
	}
	sz := maxBytes / int64(outputMaxSegments)
	if sz < 1 {
		return maxBytes
	}
	return sz
}

func OutputErrPath(dir string) string {
	return filepath.Join(dir, outputErrFile)
}

func outputSegPath(dir string, start uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%s%016d", outputSegPrefix, start))
}

func parseOutputSegName(name string) (uint64, bool) {
	if !strings.HasPrefix(name, outputSegPrefix) {
		return 0, false
	}
	rest := strings.TrimPrefix(name, outputSegPrefix)
	if rest == "" {
		return 0, false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func openOutputLog(dir string, maxBytes int64) *outputLog {
	if maxBytes <= 0 {
		maxBytes = DefaultOutputLogMax
	}
	l := &outputLog{
		dir:      dir,
		maxBytes: maxBytes,
		segSize:  outputLayout(maxBytes),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		writeAll: func(f *os.File, p []byte) (int, error) { return f.Write(p) },
	}
	l.load()
	l.wg.Add(1)
	go l.writer()
	return l
}

func (l *outputLog) load() {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	var segs []outputSeg
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		start, ok := parseOutputSegName(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		segs = append(segs, outputSeg{
			start: start,
			size:  info.Size(),
			path:  filepath.Join(l.dir, e.Name()),
		})
	}
	if len(segs) == 0 {
		return
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].start < segs[j].start })
	l.segs = segs
	l.earliest = segs[0].start
	last := segs[len(segs)-1]
	l.diskEnd = last.start + uint64(last.size)
	l.nextSeq = l.diskEnd
	l.tailStart = l.nextSeq
	var total int64
	for _, s := range segs {
		total += s.size
	}
	l.totalSize = total
	if last.size < l.segSize {
		f, err := os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			l.cur = f
			l.curSize = last.size
		}
	}
}

func (l *outputLog) writer() {
	defer l.wg.Done()
	tick := time.NewTicker(outputFlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			l.flushPending()
			l.closeFile()
			return
		case <-l.wake:
			l.flushPending()
		case <-tick.C:
			l.flushPending()
		}
	}
}

func (l *outputLog) Close() {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
		close(l.done)
		l.wg.Wait()
	})
}

func (l *outputLog) Append(p []byte) {
	if len(p) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.nextSeq += uint64(len(p))
	l.tail = append(l.tail, p...)
	if len(l.tail) > outputTailMax {
		drop := len(l.tail) - outputTailMax
		l.tail = append([]byte(nil), l.tail[drop:]...)
	}
	l.tailStart = l.nextSeq - uint64(len(l.tail))
	if l.degraded {
		return
	}
	l.pending = append(l.pending, p...)
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *outputLog) Read(cursor uint64) ReadResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readLocked(cursor)
}

func (l *outputLog) readLocked(cursor uint64) ReadResult {
	orig := cursor
	var dropped uint64
	if cursor < l.earliest {
		dropped = l.earliest - cursor
		cursor = l.earliest
	}
	if l.degraded && l.tailStart > l.diskEnd && cursor >= l.diskEnd && cursor < l.tailStart {
		dropped += l.tailStart - cursor
		cursor = l.tailStart
	}
	if cursor >= l.nextSeq {
		next := orig
		if dropped > 0 {
			next = cursor
		}
		return ReadResult{CursorNext: next, Dropped: dropped, AtEnd: true}
	}
	data := l.gatherLocked(cursor, ReadMax)
	next := cursor + uint64(len(data))
	return ReadResult{
		Data:       data,
		CursorNext: next,
		Dropped:    dropped,
		AtEnd:      next >= l.nextSeq,
	}
}

func (l *outputLog) gatherLocked(cursor uint64, want int) []byte {
	if want <= 0 {
		return nil
	}
	var out []byte
	if cursor < l.diskEnd {
		end := l.diskEnd
		if max := cursor + uint64(want); max < end {
			end = max
		}
		out = l.readDiskLocked(cursor, end)
		cursor += uint64(len(out))
	}
	if len(out) >= want {
		return out[:want]
	}
	if !l.degraded && cursor >= l.diskEnd && cursor < l.diskEnd+uint64(len(l.pending)) {
		off := int(cursor - l.diskEnd)
		chunk := l.pending[off:]
		take := want - len(out)
		if len(chunk) > take {
			chunk = chunk[:take]
		}
		out = append(out, chunk...)
		cursor += uint64(len(chunk))
	}
	if len(out) >= want {
		return out[:want]
	}
	if cursor >= l.tailStart && cursor < l.nextSeq && len(l.tail) > 0 {
		off := int(cursor - l.tailStart)
		if off >= 0 && off < len(l.tail) {
			chunk := l.tail[off:]
			take := want - len(out)
			if len(chunk) > take {
				chunk = chunk[:take]
			}
			out = append(out, chunk...)
		}
	}
	return out
}

func (l *outputLog) readDiskLocked(start, end uint64) []byte {
	if end <= start {
		return nil
	}
	var out []byte
	for _, s := range l.segs {
		segEnd := s.start + uint64(s.size)
		if start >= segEnd || end <= s.start {
			continue
		}
		from := start
		if from < s.start {
			from = s.start
		}
		to := end
		if to > segEnd {
			to = segEnd
		}
		if to <= from {
			continue
		}
		n := int(to - from)
		b := make([]byte, n)
		f, err := os.Open(s.path)
		if err != nil {
			continue
		}
		_, err = f.ReadAt(b, int64(from-s.start))
		_ = f.Close()
		if err != nil {
			continue
		}
		out = append(out, b...)
		start = to
		if start >= end {
			break
		}
	}
	return out
}

func (l *outputLog) flushPending() {
	l.mu.Lock()
	if l.degraded {
		l.mu.Unlock()
		return
	}
	if len(l.pending) == 0 {
		l.mu.Unlock()
		return
	}
	chunk := append([]byte(nil), l.pending...)
	l.mu.Unlock()

	if err := l.writeChunk(chunk); err != nil {
		l.fail(err)
		return
	}

	l.mu.Lock()
	if len(l.pending) >= len(chunk) {
		l.pending = l.pending[len(chunk):]
		l.diskEnd += uint64(len(chunk))
	}
	l.mu.Unlock()
}

func (l *outputLog) writeChunk(p []byte) error {
	for len(p) > 0 {
		l.mu.Lock()
		if l.degraded {
			l.mu.Unlock()
			return fmt.Errorf("output log degraded")
		}
		if l.cur == nil || l.curSize >= l.segSize {
			if err := l.openNewSegLocked(); err != nil {
				l.mu.Unlock()
				return err
			}
		}
		room := l.segSize - l.curSize
		if room <= 0 {
			if err := l.openNewSegLocked(); err != nil {
				l.mu.Unlock()
				return err
			}
			room = l.segSize
		}
		f := l.cur
		take := int64(len(p))
		if take > room {
			take = room
		}
		chunk := p[:take]
		p = p[take:]
		l.mu.Unlock()

		n, err := l.writeAll(f, chunk)
		if err != nil {
			return err
		}
		if n < len(chunk) {
			return fmt.Errorf("short write")
		}

		l.mu.Lock()
		l.curSize += int64(n)
		l.totalSize += int64(n)
		if len(l.segs) > 0 {
			l.segs[len(l.segs)-1].size = l.curSize
		}
		for l.totalSize > l.maxBytes && len(l.segs) > 1 {
			l.dropOldestLocked()
		}
		l.mu.Unlock()
	}
	return nil
}

func (l *outputLog) openNewSegLocked() error {
	if l.cur != nil {
		_ = l.cur.Close()
		l.cur = nil
	}
	start := l.diskEnd
	if len(l.segs) > 0 {
		last := l.segs[len(l.segs)-1]
		start = last.start + uint64(last.size)
	}
	path := outputSegPath(l.dir, start)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.cur = f
	l.curSize = 0
	l.segs = append(l.segs, outputSeg{start: start, size: 0, path: path})
	return nil
}

func (l *outputLog) dropOldestLocked() {
	if len(l.segs) == 0 {
		return
	}
	old := l.segs[0]
	_ = os.Remove(old.path)
	l.totalSize -= old.size
	if l.totalSize < 0 {
		l.totalSize = 0
	}
	l.segs = l.segs[1:]
	if len(l.segs) == 0 {
		l.earliest = l.diskEnd
		return
	}
	l.earliest = l.segs[0].start
}

func (l *outputLog) fail(err error) {
	l.mu.Lock()
	if l.degraded {
		l.mu.Unlock()
		return
	}
	l.degraded = true
	l.pending = nil
	cur := l.cur
	l.cur = nil
	l.mu.Unlock()
	if cur != nil {
		_ = cur.Close()
	}
	_ = os.WriteFile(OutputErrPath(l.dir), []byte(err.Error()+"\n"), 0o600)
}

func (l *outputLog) closeFile() {
	l.mu.Lock()
	cur := l.cur
	l.cur = nil
	l.mu.Unlock()
	if cur != nil {
		_ = cur.Close()
	}
}

func (l *outputLog) Degraded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.degraded
}

// readOutputFiles serves a read from disk only. Used when the agent is gone
// and the unflushed tail died with it.
func readOutputFiles(dir string, cursor uint64) ReadResult {
	l := &outputLog{dir: dir, maxBytes: DefaultOutputLogMax, segSize: outputLayout(DefaultOutputLogMax)}
	l.load()
	l.nextSeq = l.diskEnd
	l.tailStart = l.nextSeq
	return l.readLocked(cursor)
}

// ReadSession pulls output for a live dir. A running agent includes bytes
// that have not been flushed yet. A dead agent can only return what reached
// disk; bytes lost with the process are gone.
func ReadSession(dir string, cursor uint64) (ReadResult, error) {
	if Alive(dir) {
		return DialRead(dir, cursor)
	}
	return readOutputFiles(dir, cursor), nil
}
