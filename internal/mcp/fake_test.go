package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"tyd/internal/ttyutil"
)

// fakeBackend is a scripted tyd for the tool tests. It holds the sessions in
// memory and never opens a socket, so a test can drive a whole exchange without
// a daemon.
type fakeBackend struct {
	mu sync.Mutex

	sessions map[string]*fakeSession
	// nextID numbers the sessions Open hands out.
	nextID int
	// peerSeen records the peer each call resolved against, so a test can check
	// that a property the schema offers really reaches the target.
	peerSeen func(peer string)
	// openErr, sendErr, readErr and closeErr fail the matching call, once.
	openErr  error
	sendErr  error
	readErr  error
	closeErr error
	// readErrFor fails a read for one session, every time. A target in pre mode
	// refuses every read until it is approved, which readErr's one-shot cannot
	// express.
	readErrFor func(sessionID string) error
	// reads counts every read that reached the target, so a test can assert a
	// list did not spend an approval on a probe.
	reads int
	// filePage and fileWritten are what the fake file operations return; fileCalls
	// records what they were asked, which is how the tool layer is tested without a
	// filesystem.
	filePage     FilePage
	fileWritten  FileWritten
	fileReadErr  error
	fileWriteErr error
	fileCalls    []fileCall
	// targets are the machines the fake serves, for a fan-out test. Nil means the
	// local daemon alone.
	targets []Target
	// readDelay makes one machine's read answer later, so reply order differs from
	// request order. Keyed by peer label.
	readDelay map[string]time.Duration
	// readHang makes one machine accept a read and then never answer, which is how
	// a per-target timeout gets exercised without a real timeout.
	readHang map[string]bool
	// readHook runs inside every read. A test uses it to assert something about the
	// caller's state at that moment — which is where a lock held across IO shows up.
	readHook func()
	// beforeRelease runs just before a probe hands its slot back, so a test can
	// pause in the gap between recording the state and releasing the slot.
	beforeRelease func()
	// approvalAsks counts reads refused pending approval, which is the operator's
	// approval being asked for.
	approvalAsks int
	// alias maps a reference to a session id, like the local alias file.
	alias map[string]string
	// calls records the order the tools reached the target in.
	calls []string
	// sendGate, when set, parks every send until it is closed. A test uses it to
	// cancel a send that is already writing.
	sendGate chan struct{}
	// echoState is the line discipline this fake terminal reports, so a test can
	// make the refusal paths reachable. Nil means the default.
	echoState *fakeEcho
	// readGate, when set, parks every read until it is closed. A test uses it to
	// hold a read open and cancel it.
	readGate chan struct{}
	// gateOpen records whether readGate is still open, so a test can release it
	// without closing it twice.
	gateOpen bool
	// readWait records the wait a read was given, so a default can be checked.
	readWait []time.Duration
	// readCond records the conditions a read was given.
	readCond []Wait
	// blocked reports how many reads are parked right now.
	blocked int
	// sending_ reports how many sends are parked right now.
	sending_ int
	// peakBlocked is the high-water mark, which is what the serialization test
	// asserts on: sampling blocked from the test would race.
	peakBlocked int
}

type fakeSession struct {
	id    string
	alias string
	// peer is the machine this session lives on, which the catalog would have
	// recorded. Empty means the local daemon.
	peer string
	// root is the narrowing session_open was given, recorded so the tool layer can be
	// tested without a filesystem. It belongs to the session, so every later file call
	// starts from it.
	root string
	// log is the output stream, appended to by send.
	log []byte
	// exited marks a shell that has ended.
	exited bool
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		sessions: map[string]*fakeSession{},
		alias:    map[string]string{},
	}
}

func (f *fakeBackend) Open(_ context.Context, req OpenRequest) (Opened, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peerSeen != nil {
		f.peerSeen(req.Peer)
	}
	if f.openErr != nil {
		return Opened{}, f.openErr
	}
	f.nextID++
	id := "sess" + string(rune('0'+f.nextID))
	s := &fakeSession{id: id, alias: req.Name, root: req.Root}
	f.sessions[id] = s
	if req.Name != "" {
		f.alias[req.Name] = id
	}
	f.calls = append(f.calls, "open "+id)
	return Opened{
		Session:     Session{ID: id, Alias: req.Name},
		HumanAttach: "tyd session attach " + req.Name,
		State:       "DETACHED",
	}, nil
}

func (f *fakeBackend) Resolve(_ context.Context, ref, peer string) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peerSeen != nil {
		f.peerSeen(peer)
	}
	id := f.alias[ref]
	if id == "" {
		id = ref
	}
	if _, ok := f.sessions[id]; !ok {
		return Session{}, errors.New("unknown session " + ref)
	}
	// Root travels with the resolved session, as it does for the real backend: it
	// belongs to the session, so a file call starts from it without the caller having
	// to repeat it.
	return Session{ID: id, Alias: f.aliases(id), Root: f.sessions[id].root}, nil
}

func (f *fakeBackend) aliases(id string) string {
	for name, sid := range f.alias {
		if sid == id {
			return name
		}
	}
	return ""
}

func (f *fakeBackend) List(context.Context) ([]Listed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Listed, 0, len(f.sessions))
	for id, s := range f.sessions {
		out = append(out, Listed{
			Session:  Session{ID: id, Alias: s.alias, Peer: s.peer},
			Recorded: "DETACHED",
		})
	}
	return out, nil
}

func (f *fakeBackend) Send(ctx context.Context, s Session, data []byte, secret bool) (Sent, error) {
	// A fake terminal is never a password prompt, so it echoes. That makes it the
	// right shape for a refusal test and the wrong shape for a happy path, so the
	// state is a field rather than a constant.
	f.mu.Lock()
	gate := f.sendGate
	echoState := f.echoState
	f.mu.Unlock()
	if secret && echoState != nil {
		st := ttyutil.EchoState{Echo: echoState.echo, Icanon: echoState.icanon}
		if st.InputMode() == ttyutil.InputEcho {
			return Sent{}, errors.New("refused: the terminal is echoing")
		}
	}
	if gate != nil {
		// A real target accepts the bytes and then answers, so a send cut off
		// part way knows it wrote some and not how many.
		f.mu.Lock()
		f.sending_++
		f.mu.Unlock()
		select {
		case <-gate:
		case <-ctx.Done():
			f.mu.Lock()
			f.sending_--
			f.mu.Unlock()
			return Sent{}, ctx.Err()
		}
		f.mu.Lock()
		f.sending_--
		f.mu.Unlock()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return Sent{Cursor: 0, Epoch: 1}, f.sendErr
	}
	sess, ok := f.sessions[s.ID]
	if !ok {
		return Sent{}, errors.New("unknown session " + s.ID)
	}
	f.calls = append(f.calls, "send "+s.ID)
	if sess.exited {
		return Sent{Cursor: uint64(len(sess.log)), Epoch: 1}, errors.New("session has no running agent; send needs a live shell")
	}
	// The append of a prompt after the keys is what a shell does, so a test can
	// tell a real echo from nothing.
	sess.log = append(sess.log, data...)
	sess.log = append(sess.log, "\r\n$ "...)
	return Sent{
		Written:      len(data),
		WrittenKnown: true,
		Cursor:       uint64(len(sess.log) - len(data) - 4),
		Epoch:        1,
	}, nil
}

func (f *fakeBackend) Read(ctx context.Context, req ReadRequest) (Page, error) {
	f.mu.Lock()
	if f.readErr != nil {
		err := f.readErr
		f.mu.Unlock()
		return Page{}, err
	}
	sess, ok := f.sessions[req.Session.ID]
	if !ok {
		f.mu.Unlock()
		return Page{}, errors.New("unknown session " + req.Session.ID)
	}
	f.reads++
	log := append([]byte(nil), sess.log...)
	exited := sess.exited
	peer := peerOf(req)
	// Read everything a seam needs while the lock is held, then let it go: a seam
	// that blocks must not hold the fake's own lock, or a test that releases it
	// would block on the release.
	hook, before := f.readHook, f.beforeRelease
	delay := f.readDelay[peer]
	hang := f.readHang[peer]
	errFor := f.readErrFor
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	if before != nil {
		before()
	}
	if hang {
		// Accepted and then silent: what a per-target timeout exists for.
		<-ctx.Done()
		return Page{}, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return Page{}, ctx.Err()
		}
	}
	if errFor != nil {
		if err := errFor(req.Session.ID); err != nil {
			if strings.Contains(err.Error(), "pending approval") {
				f.mu.Lock()
				f.approvalAsks++
				f.mu.Unlock()
			}
			return Page{}, err
		}
	}
	_ = exited

	// Taken again for the gate: the seam above released the lock so a blocking
	// hook could not hold it, and this section still needs it for the counters.
	f.mu.Lock()
	gate := f.readGate
	f.readWait = append(f.readWait, req.Wait)
	f.readCond = append(f.readCond, req.Cond)
	if gate != nil {
		f.blocked++
		if f.blocked > f.peakBlocked {
			f.peakBlocked = f.blocked
		}
		f.mu.Unlock()
		select {
		case <-gate:
		case <-ctx.Done():
			f.mu.Lock()
			f.blocked--
			f.mu.Unlock()
			return Page{}, ctx.Err()
		}
		f.mu.Lock()
		f.blocked--
		sess, ok = f.sessions[req.Session.ID]
		if !ok {
			f.mu.Unlock()
			return Page{}, errors.New("unknown session " + req.Session.ID)
		}
		log = append([]byte(nil), sess.log...)
		exited = sess.exited
	}
	defer f.mu.Unlock()

	start := int(req.Cursor)
	if start > len(log) {
		start = 0
	}
	data := log[start:]
	next := uint64(len(log))
	if req.Cond.MaxBytes > 0 && len(data) > int(req.Cond.MaxBytes) {
		next = req.Cursor + uint64(req.Cond.MaxBytes)
		data = data[:req.Cond.MaxBytes]
	}
	reason := "available"
	switch {
	case exited:
		reason = "exited"
	case req.Cond.IdleMS > 0:
		reason = "idle"
	case req.Cond.Match != "":
		reason = "match"
	case req.Cond.MaxBytes > 0:
		reason = "max_bytes"
	}
	return Page{Data: data, CursorNext: next, Epoch: 1, Exited: exited, Reason: reason}, nil
}

func (f *fakeBackend) Close(_ context.Context, s Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	delete(f.sessions, s.ID)
	f.calls = append(f.calls, "close "+s.ID)
	return nil
}

// sending reports how many sends are parked right now.
func (f *fakeBackend) sending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sending_
}

// parked reports how many reads are parked right now, so a test can wait for a
// follow-up read to be under way before it withdraws the call.
func (f *fakeBackend) parked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocked > 0
}

// parkSends makes every later send block until the returned channel is closed,
// so a test can cancel a send while it is in flight.
func (f *fakeBackend) parkSends() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	gate := make(chan struct{})
	f.sendGate, f.gateOpen = gate, true
	return gate
}

// unparkSends releases the sends a parkSends held and lets later sends through.
func (f *fakeBackend) unparkSends() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gateOpen {
		close(f.sendGate)
	}
	f.sendGate, f.gateOpen = nil, false
}

// parkReads makes every later read block until the returned channel is closed.
func (f *fakeBackend) parkReads() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	gate := make(chan struct{})
	f.readGate, f.gateOpen = gate, true
	return gate
}

// unparkReads releases the reads a parkReads held and lets later reads through.
func (f *fakeBackend) unparkReads() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gateOpen {
		close(f.readGate)
	}
	f.readGate, f.gateOpen = nil, false
}

// grow appends to a session's stream, which is what output from a running
// command looks like. The ref is an alias or an id, as a tool argument would be.
func (f *fakeBackend) grow(ref string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[f.alias[ref]]
	if s == nil {
		f.alias[ref] = ref
		s = f.sessions[ref]
	}
	if s == nil {
		panic("no session " + ref)
	}
	s.log = append(s.log, bytes.Repeat([]byte("out\n"), n/4)...)
}

// catalogOnly records a session that this process did not open, which is what
// the catalog holds after the agent that made it is gone.
func (f *fakeBackend) catalogOnly(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[ref]; !ok {
		f.sessions[ref] = &fakeSession{id: ref, alias: ref}
	}
}

// testServer wires a server to a fake backend with logging off.
func testServer(b Backend, mutate func(*Options)) *server {
	opts := Options{MaxSessions: 4}
	if mutate != nil {
		mutate(&opts)
	}
	return newServer(b, &logger{}, opts)
}

// testServerWithLog is testServer with somewhere for the log to go, so a test can
// read what the tools wrote about themselves.
func testServerWithLog(b Backend, w io.Writer) *server {
	return newServer(b, newLogger(w), Options{MaxSessions: 4})
}

// readCount is how many reads have reached the target.
func (f *fakeBackend) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// resetReads starts the count again, so a test can measure one call rather than
// everything before it.
func (f *fakeBackend) resetReads() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = 0
}

// fakeEcho is a line-discipline state a test sets on the fake terminal.
type fakeEcho struct{ echo, icanon bool }

// setEchoState makes the fake terminal report this state, which is what makes a
// refusal reachable without a real program asking for a secret.
func (f *fakeBackend) setEchoState(echo, icanon bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.echoState = &fakeEcho{echo: echo, icanon: icanon}
}

// Targets names the machines the fake serves. A test sets peers to make several.
func (f *fakeBackend) Targets(context.Context) ([]Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.targets != nil {
		return append([]Target(nil), f.targets...), nil
	}
	return []Target{{Label: "", Identity: "", Local: true}}, nil
}

// setTargets makes the fake serve these machines, for a fan-out test.
func (f *fakeBackend) setTargets(ts ...Target) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = ts
}

// The seams a fan-out test needs: per-machine read delays, a machine that accepts
// and then stops answering, a hook that runs inside a read, and the high-water mark
// of simultaneous parked reads.
var _ = 0

// peerOf is the machine a read is for, which the fake keys its per-machine seams by.
func peerOf(req ReadRequest) string {
	if req.Session.Peer == "" {
		return ""
	}
	return req.Session.Peer
}

func (f *fakeBackend) peakBlockedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peakBlocked
}

func (f *fakeBackend) setReadDelay(peer string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readDelay == nil {
		f.readDelay = map[string]time.Duration{}
	}
	f.readDelay[peer] = d
}

func (f *fakeBackend) setReadHang(peer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readHang == nil {
		f.readHang = map[string]bool{}
	}
	f.readHang[peer] = true
}

// setReadHook runs fn inside every read, so a test can assert something about the
// caller's state at that moment — which is where a lock held across IO shows up.
func (f *fakeBackend) setReadHook(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readHook = fn
}

// approvalRequests counts reads that were refused pending approval, which is the
// operator's approval being asked for.
func (f *fakeBackend) approvalRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approvalAsks
}

// beforeRelease runs just before a probe hands its slot back, so a test can pause in
// the gap between recording the state and releasing the slot.
func (f *fakeBackend) setBeforeRelease(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beforeRelease = fn
}

// The file operations, so the tool layer can be tested without a filesystem. The
// paths are recorded rather than interpreted, which is the point: the fake has no root
// and no opinion, exactly as the real backend has none.
func (f *fakeBackend) FileRead(ctx context.Context, s Session, req FileRequest) (FilePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fileReadErr != nil {
		return FilePage{}, f.fileReadErr
	}
	if _, ok := f.sessions[s.ID]; !ok {
		return FilePage{}, errors.New("unknown session " + s.ID)
	}
	f.fileCalls = append(f.fileCalls, fileCall{op: "read", session: s.ID, req: req})
	if f.filePage.Size == 0 {
		return FilePage{Data: f.filePage.Data}, nil
	}
	return f.filePage, nil
}

func (f *fakeBackend) FileWrite(ctx context.Context, s Session, req FileWriteRequest) (FileWritten, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fileWriteErr != nil {
		return FileWritten{}, f.fileWriteErr
	}
	if _, ok := f.sessions[s.ID]; !ok {
		return FileWritten{}, errors.New("unknown session " + s.ID)
	}
	f.fileCalls = append(f.fileCalls, fileCall{op: "write", session: s.ID, write: req})
	return f.fileWritten, nil
}

// fileCall is one recorded file operation.
type fileCall struct {
	op      string
	session string
	req     FileRequest
	write   FileWriteRequest
}
