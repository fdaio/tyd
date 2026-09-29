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
	outputSeqFile    = "output.seq"
	outputEpochFile  = "output.epoch"
	outputCleanFile  = "output.clean"
	outputBoundFile  = "output.bound"
)

// ReadResult is one non-blocking pull from the sequenced output log.
type ReadResult struct {
	Data        []byte
	CursorNext  uint64
	Dropped     uint64
	AtEnd       bool
	Epoch       uint64
	CursorAhead bool // stale cursor or epoch; adopt CursorNext and Epoch
}

type outputSeg struct {
	start uint64
	size  int64
	path  string
}

type readSnap struct {
	earliest      uint64
	nextSeq       uint64
	diskEnd       uint64
	tailStart     uint64
	epoch         uint64
	epochBoundary uint64
	pending       []byte
	tail          []byte
	segs          []outputSeg
	degraded      bool
}

// outputLog assigns a monotonic byte seq and writes segments on disk.
//
// Seq starts at 0 for the session. read flushes pending bytes to the kernel
// before it replies, so a kill -9 of this process cannot leave a client
// cursor past what is on disk. Epoch still bumps on an unclean restart so a
// power loss (or a disk-full hole) cannot reuse offsets the client already
// saw. A stale epoch still serves cursors within that restart's durable
// end; only a cursor past it returns cursor_ahead. The PTY path never
// waits on a disk write.
type outputLog struct {
	dir      string
	maxBytes int64
	segSize  int64

	mu            sync.Mutex
	flushMu       sync.Mutex
	earliest      uint64
	nextSeq       uint64
	diskEnd       uint64
	pending       []byte
	tail          []byte
	tailStart     uint64
	segs          []outputSeg
	cur           *os.File
	curSize       int64
	totalSize     int64
	degraded      bool
	closed        bool
	epoch         uint64
	epochBoundary uint64
	skipFlush     bool
	pauseFlush    bool

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

func readUintFile(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func writeUintFile(path string, n uint64) error {
	return os.WriteFile(path, []byte(strconv.FormatUint(n, 10)+"\n"), 0o600)
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
	l.restoreFiles()
	l.applyUncleanEpoch()
	l.attachCurrentSeg()
	l.wg.Add(1)
	go l.writer()
	return l
}

func (l *outputLog) restoreFiles() {
	ents, err := os.ReadDir(l.dir)
	if err != nil && !os.IsNotExist(err) {
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
	if len(segs) > 0 {
		sort.Slice(segs, func(i, j int) bool { return segs[i].start < segs[j].start })
		l.segs = segs
		l.earliest = segs[0].start
		last := segs[len(segs)-1]
		l.diskEnd = last.start + uint64(last.size)
		l.nextSeq = l.diskEnd
		var total int64
		for _, s := range segs {
			total += s.size
		}
		l.totalSize = total
	}
	if n, ok := readUintFile(filepath.Join(l.dir, outputSeqFile)); ok && n > l.nextSeq {
		l.nextSeq = n
	}
	l.tailStart = l.nextSeq
	if n, ok := readUintFile(filepath.Join(l.dir, outputEpochFile)); ok && n > 0 {
		l.epoch = n
	}
	if n, ok := readUintFile(filepath.Join(l.dir, outputBoundFile)); ok {
		l.epochBoundary = n
	} else {
		l.epochBoundary = l.diskEnd
	}
}

func (l *outputLog) attachCurrentSeg() {
	if len(l.segs) == 0 {
		return
	}
	last := l.segs[len(l.segs)-1]
	end := last.start + uint64(last.size)
	// A crash can leave nextSeq past the last file. Do not append into that
	// file; the next flush opens a segment at nextSeq and leaves the hole.
	if end != l.nextSeq || last.size >= l.segSize {
		return
	}
	f, err := os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	l.cur = f
	l.curSize = last.size
}

// applyUncleanEpoch assigns the log generation. output.clean is written only
// after a clean Close (flush, then persistMeta(true)). kill -9, a crash, or
// abandon() leave that file missing. The next open treats a missing clean
// file plus any prior seq/epoch/segments as an unclean restart and bumps
// epoch. A present clean file is consumed immediately, so a running process
// is again "not cleanly closed" until the next Close.
func (l *outputLog) applyUncleanEpoch() {
	epoch := l.epoch
	cleanPath := filepath.Join(l.dir, outputCleanFile)
	_, cleanErr := os.Stat(cleanPath)
	prior := len(l.segs) > 0 || epoch > 0 || l.nextSeq > 0
	bumped := false
	if cleanErr == nil {
		_ = os.Remove(cleanPath)
		if epoch == 0 {
			epoch = 1
		}
	} else if prior {
		epoch++
		bumped = true
	}
	if epoch == 0 {
		epoch = 1
	}
	l.epoch = epoch
	if bumped {
		l.epochBoundary = l.diskEnd
	}
	_ = writeUintFile(filepath.Join(l.dir, outputEpochFile), epoch)
	_ = writeUintFile(filepath.Join(l.dir, outputBoundFile), l.epochBoundary)
}

func (l *outputLog) writer() {
	defer l.wg.Done()
	tick := time.NewTicker(outputFlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			l.mu.Lock()
			skip := l.skipFlush
			l.mu.Unlock()
			if !skip {
				l.flushPending()
				l.persistMeta(true)
			}
			l.closeFile()
			return
		case <-l.wake:
			if l.writerFlushPaused() {
				continue
			}
			l.flushPending()
		case <-tick.C:
			if l.writerFlushPaused() {
				continue
			}
			l.flushPending()
		}
	}
}

func (l *outputLog) persistMeta(clean bool) {
	l.mu.Lock()
	n := l.diskEnd
	if l.degraded && l.nextSeq > n {
		n = l.nextSeq
	}
	dir := l.dir
	l.mu.Unlock()
	_ = writeUintFile(filepath.Join(dir, outputSeqFile), n)
	if clean {
		_ = os.WriteFile(filepath.Join(dir, outputCleanFile), []byte("ok\n"), 0o600)
	}
}

func (l *outputLog) writerFlushPaused() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pauseFlush
}

// pauseWriterFlush keeps the background writer from draining pending. Tests
// use it so abandon() can stand in for kill -9 before a flush.
func (l *outputLog) pauseWriterFlush() {
	l.mu.Lock()
	l.pauseFlush = true
	l.mu.Unlock()
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

// abandon stops the writer without flushing pending bytes. Tests use it
// to stand in for kill -9.
func (l *outputLog) abandon() {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.skipFlush = true
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
	return l.ReadAt(cursor, 0)
}

func (l *outputLog) ReadAt(cursor, reqEpoch uint64) ReadResult {
	l.mu.Lock()
	skip := l.skipFlush
	// Bound the reply to the seq the flush below is about to cover. An Append
	// that lands after this point is not in the reply, so it cannot be
	// acknowledged as durable.
	limit := l.nextSeq
	l.mu.Unlock()
	if !skip {
		l.flushPending()
	}
	l.mu.Lock()
	snap := l.snapshotLocked()
	l.mu.Unlock()
	// Replies only include bytes already given to the kernel, except the
	// disk-full path which still serves the in-memory tail.
	snap.pending = nil
	if !snap.degraded {
		snap.tail = nil
	}
	if snap.nextSeq > limit {
		snap.nextSeq = limit
		snap.tailStart = limit
		snap.diskEnd = limit
	}
	return readFromSnap(snap, cursor, reqEpoch)
}

func (l *outputLog) snapshotLocked() readSnap {
	return readSnap{
		earliest:      l.earliest,
		nextSeq:       l.nextSeq,
		diskEnd:       l.diskEnd,
		tailStart:     l.tailStart,
		epoch:         l.epoch,
		epochBoundary: l.epochBoundary,
		pending:       append([]byte(nil), l.pending...),
		tail:          append([]byte(nil), l.tail...),
		segs:          append([]outputSeg(nil), l.segs...),
		degraded:      l.degraded,
	}
}

func readFromSnap(s readSnap, cursor, reqEpoch uint64) ReadResult {
	res := ReadResult{Epoch: s.epoch}
	resumeAt := s.nextSeq
	stale := reqEpoch != 0 && reqEpoch != s.epoch

	if cursor > s.nextSeq {
		res.CursorAhead = true
		res.CursorNext = resumeAt
		res.AtEnd = true
		return res
	}

	orig := cursor
	var dropped uint64
	if cursor < s.earliest {
		dropped = s.earliest - cursor
		cursor = s.earliest
	}

	if stale {
		bound := s.epochBoundary
		if cursor > bound {
			res.CursorAhead = true
			res.CursorNext = resumeAt
			res.Dropped = dropped
			res.AtEnd = true
			return res
		}
		s.nextSeq = bound
		s.diskEnd = bound
		s.pending = nil
		s.tail = nil
		s.degraded = false
		s.tailStart = bound
	} else if s.degraded && s.tailStart > s.diskEnd && cursor >= s.diskEnd && cursor < s.tailStart {
		dropped += s.tailStart - cursor
		cursor = s.tailStart
	}

	if cursor >= s.nextSeq {
		next := orig
		if dropped > 0 {
			next = cursor
		}
		res.CursorNext = next
		res.Dropped = dropped
		res.AtEnd = true
		return res
	}

	data, skip, gap := gatherSnap(s, cursor, ReadMax)
	if gap {
		res.CursorAhead = true
		res.Dropped = dropped
		res.CursorNext = resumeAt
		res.AtEnd = true
		return res
	}
	if skip > 0 {
		dropped += skip
		cursor += skip
		more, skip2, gap2 := gatherSnap(s, cursor, ReadMax)
		if gap2 {
			res.CursorAhead = true
			res.Dropped = dropped
			res.CursorNext = resumeAt
			res.AtEnd = true
			return res
		}
		dropped += skip2
		data = more
	}
	if len(data) == 0 && cursor < s.nextSeq {
		res.CursorAhead = true
		res.Dropped = dropped
		res.CursorNext = resumeAt
		res.AtEnd = true
		return res
	}
	next := cursor + uint64(len(data))
	res.Data = data
	res.CursorNext = next
	res.Dropped = dropped
	res.AtEnd = next >= s.nextSeq
	return res
}

func pendingStart(s readSnap) uint64 {
	if len(s.pending) == 0 {
		return s.nextSeq
	}
	return s.nextSeq - uint64(len(s.pending))
}

func gatherSnap(s readSnap, cursor uint64, want int) ([]byte, uint64, bool) {
	if want <= 0 {
		return nil, 0, false
	}
	var out []byte
	pStart := pendingStart(s)
	if cursor < pStart {
		end := pStart
		if max := cursor + uint64(want); max < end {
			end = max
		}
		chunk, hole, gap := readDiskSnap(s.segs, cursor, end)
		if len(chunk) == 0 {
			if gap {
				return nil, 0, true
			}
			if hole > 0 {
				return nil, hole, false
			}
		} else if gap {
			return chunk, 0, false
		} else {
			out = chunk
			cursor += uint64(len(out))
		}
	}
	if len(out) >= want {
		return out[:want], 0, false
	}
	if !s.degraded && cursor >= pStart && cursor < s.nextSeq {
		off := int(cursor - pStart)
		if off >= 0 && off < len(s.pending) {
			chunk := s.pending[off:]
			take := want - len(out)
			if len(chunk) > take {
				chunk = chunk[:take]
			}
			out = append(out, chunk...)
			cursor += uint64(len(chunk))
		}
	}
	if len(out) >= want {
		return out[:want], 0, false
	}
	if cursor >= s.tailStart && cursor < s.nextSeq && len(s.tail) > 0 {
		off := int(cursor - s.tailStart)
		if off >= 0 && off < len(s.tail) {
			chunk := s.tail[off:]
			take := want - len(out)
			if len(chunk) > take {
				chunk = chunk[:take]
			}
			out = append(out, chunk...)
		}
	}
	return out, 0, false
}

func readDiskSnap(segs []outputSeg, start, end uint64) ([]byte, uint64, bool) {
	if end <= start {
		return nil, 0, false
	}
	var out []byte
	cur := start
	for _, s := range segs {
		segEnd := s.start + uint64(s.size)
		if cur >= segEnd || end <= s.start {
			continue
		}
		if s.start > cur {
			return out, s.start - cur, true
		}
		from := cur
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
			return out, uint64(n), false
		}
		_, err = f.ReadAt(b, int64(from-s.start))
		_ = f.Close()
		if err != nil {
			return out, uint64(n), false
		}
		out = append(out, b...)
		cur = to
		if cur >= end {
			break
		}
	}
	return out, 0, false
}

func (l *outputLog) flushPending() {
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

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
	chunkStart := l.nextSeq - uint64(len(l.pending))
	l.mu.Unlock()

	if err := l.writeChunk(chunk, chunkStart); err != nil {
		l.fail(err)
		return
	}

	l.mu.Lock()
	if len(l.pending) >= len(chunk) {
		l.pending = l.pending[len(chunk):]
	}
	durable := l.diskEnd
	dir := l.dir
	l.mu.Unlock()
	_ = writeUintFile(filepath.Join(dir, outputSeqFile), durable)
}

func (l *outputLog) writeChunk(p []byte, start uint64) error {
	off := start
	for len(p) > 0 {
		l.mu.Lock()
		if l.degraded {
			l.mu.Unlock()
			return fmt.Errorf("output log degraded")
		}
		if l.cur == nil || l.curSize >= l.segSize {
			if err := l.openNewSegLocked(off); err != nil {
				l.mu.Unlock()
				return err
			}
		}
		room := l.segSize - l.curSize
		if room <= 0 {
			if err := l.openNewSegLocked(off); err != nil {
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
		off += uint64(n)

		l.mu.Lock()
		l.curSize += int64(n)
		l.totalSize += int64(n)
		if len(l.segs) > 0 {
			l.segs[len(l.segs)-1].size = l.curSize
			end := l.segs[len(l.segs)-1].start + uint64(l.curSize)
			if end > l.diskEnd {
				l.diskEnd = end
			}
		}
		var dropped []string
		for l.totalSize > l.maxBytes && len(l.segs) > 1 {
			if p := l.dropOldestLocked(); p != "" {
				dropped = append(dropped, p)
			}
		}
		l.mu.Unlock()
		for _, p := range dropped {
			_ = os.Remove(p)
		}
	}
	return nil
}

func (l *outputLog) openNewSegLocked(start uint64) error {
	if l.cur != nil {
		_ = l.cur.Close()
		l.cur = nil
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

func (l *outputLog) dropOldestLocked() string {
	if len(l.segs) == 0 {
		return ""
	}
	old := l.segs[0]
	l.totalSize -= old.size
	if l.totalSize < 0 {
		l.totalSize = 0
	}
	l.segs = l.segs[1:]
	if len(l.segs) == 0 {
		l.earliest = l.diskEnd
	} else {
		l.earliest = l.segs[0].start
	}
	return old.path
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

func (l *outputLog) Epoch() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.epoch
}

// readOutputFiles serves a read from disk and the persisted seq high-water
// mark when the agent is gone.
func readOutputFiles(dir string, cursor, epoch uint64) ReadResult {
	l := &outputLog{dir: dir, maxBytes: DefaultOutputLogMax, segSize: outputLayout(DefaultOutputLogMax)}
	l.restoreFiles()
	if l.epoch == 0 {
		l.epoch = 1
	}
	return l.ReadAt(cursor, epoch)
}

// ReadSession pulls output for a live dir. A running agent flushes pending
// bytes before the reply, so the cursor only advances over data already
// given to the kernel. A dead agent can only return what reached disk. A
// hole (assigned seq that never reached disk — power loss, or disk-full
// then restart) returns cursor_ahead.
func ReadSession(dir string, cursor, epoch uint64) (ReadResult, error) {
	if Alive(dir) {
		return DialRead(dir, cursor, epoch)
	}
	return readOutputFiles(dir, cursor, epoch), nil
}
