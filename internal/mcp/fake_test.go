package mcp

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

// fakeBackend is a scripted tyd for the tool tests. It holds the sessions in
// memory and never opens a socket, so a test can drive a whole exchange without
// a daemon.
type fakeBackend struct {
	mu sync.Mutex

	sessions map[string]*fakeSession
	// nextID numbers the sessions Open hands out.
	nextID int
	// openErr, sendErr, readErr and closeErr fail the matching call, once.
	openErr  error
	sendErr  error
	readErr  error
	closeErr error
	// alias maps a reference to a session id, like the local alias file.
	alias map[string]string
	// calls records the order the tools reached the target in.
	calls []string
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
	// peakBlocked is the high-water mark, which is what the serialization test
	// asserts on: sampling blocked from the test would race.
	peakBlocked int
}

type fakeSession struct {
	id    string
	alias string
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
	if f.openErr != nil {
		return Opened{}, f.openErr
	}
	f.nextID++
	id := "sess" + string(rune('0'+f.nextID))
	s := &fakeSession{id: id, alias: req.Name}
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

func (f *fakeBackend) Resolve(_ context.Context, ref, _ string) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.alias[ref]
	if id == "" {
		id = ref
	}
	if _, ok := f.sessions[id]; !ok {
		return Session{}, errors.New("unknown session " + ref)
	}
	return Session{ID: id, Alias: f.aliases(id)}, nil
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
		out = append(out, Listed{Session: Session{ID: id, Alias: s.alias}, Recorded: "DETACHED"})
	}
	return out, nil
}

func (f *fakeBackend) Send(_ context.Context, s Session, data []byte) (Sent, error) {
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
	return Sent{Written: len(data), Cursor: uint64(len(sess.log) - len(data) - 4), Epoch: 1}, nil
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
	log := append([]byte(nil), sess.log...)
	exited := sess.exited
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
