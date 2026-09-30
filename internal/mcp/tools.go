package mcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"tyd/internal/strutil"
)

const (
	// maxSendBytes caps one send. The daemon allows more, but a model that
	// pastes a file into a send gets a refusal it can act on, instead of a
	// partial write it has to reconcile.
	maxSendBytes = 2 << 10
	// maxWaitMS is the daemon's own ceiling on a parked read.
	maxWaitMS = 30_000
	// maxResultBytes caps a page a caller asks for by its own argument.
	maxResultBytes = 64 << 10
	// defaultReadWaitMS is the wait session_read uses when the caller gives
	// none. Long enough to catch a prompt, short enough that a model is not left
	// waiting on a silent session.
	defaultReadWaitMS = 2_000
	// defaultSendIdleMS and defaultSendWaitMS bracket a send: the read gives up
	// once the output has been quiet this long, and never waits longer.
	defaultSendIdleMS = 1_500
	defaultSendWaitMS = 10_000
	// interruptIdleMS and interruptWaitMS bound the read after an interrupt. A
	// shell that ignores the interrupt never answers, and the model gets an
	// answer either way.
	interruptIdleMS = 500
	interruptWaitMS = 3_000
	// approvalDeadline is how long this side waits for a human to approve a
	// remote session. The request on the target keeps waiting, so a later retry
	// can still succeed.
	approvalDeadline = 30 * time.Second
	// maxSessions bounds the sessions one process holds.
	maxSessions = 8
)

// Options is what the command line passes down.
type Options struct {
	// ReadOnly registers only the tools that change nothing on a target.
	ReadOnly bool
	// Peers are the targets this process serves. The first is the default; an
	// empty element means the local daemon. A tool takes a peer argument only
	// when there is more than one.
	Peers []string
	// MaxSessions bounds the sessions this process holds. Zero means the default.
	MaxSessions int
	// CloseOnExit ends the sessions this process opened when it stops.
	CloseOnExit bool
}

// server holds the tool set and the per-session state.
type server struct {
	backend Backend
	log     *logger

	// readOnly registers only the tools that change nothing: list and read. The
	// rest are absent from tools/list, not merely refused: a model that cannot
	// see a tool does not try it.
	readOnly bool
	// peers are the targets this process serves. A tool takes a peer argument
	// only when there is more than one, because letting a model choose the
	// machine is a privilege.
	peers []string
	// maxSessions bounds concurrent sessions.
	maxSessions int
	// closeOnExit ends the sessions this process opened when it stops, for a
	// one-shot run. The default leaves them, like tmux.
	closeOnExit bool

	mu       sync.Mutex
	sessions map[string]*sessionState
	// order is the open order, so the cap and closeOnExit act on the same list.
	order []string
	// pending counts the opens that reserved a slot but have not been adopted
	// yet. Without it two opens arriving together both see room for one.
	pending int
	// aliases maps a requested alias to its session key, so a name cannot be
	// handed to two sessions this process opened.
	aliases map[string]string
}

type sessionState struct {
	// mu serializes the tool calls on one session. Two at once would share the
	// cursor and either duplicate output or skip it, and a send in flight would
	// be refused by the target as busy anyway.
	mu sync.Mutex
	// session is the session this state belongs to, empty while the name is
	// only reserved.
	session Session
	// aliasName is the alias this process gave the session, empty when it was
	// not opened here.
	aliasName string
	// cursor is where the next read continues.
	cursor uint64
	// epoch identifies the target's output stream. A target that restarted
	// changes it, and a cursor from the old stream would be meaningless.
	epoch uint64
	// touched records that this process has read the session once. Before the
	// first read there is no position to continue from.
	touched bool
	// openedByUs marks a session this process created.
	openedByUs bool
}

// newServer wires a tool set. log receives one line per call.
func newServer(b Backend, log *logger, cfg Options) *server {
	peers := cfg.Peers
	if len(peers) == 0 {
		peers = []string{""}
	}
	max := cfg.MaxSessions
	if max <= 0 {
		max = maxSessions
	}
	return &server{
		backend:     b,
		log:         log,
		readOnly:    cfg.ReadOnly,
		peers:       peers,
		maxSessions: max,
		closeOnExit: cfg.CloseOnExit,
		sessions:    map[string]*sessionState{},
		aliases:     map[string]string{},
	}
}

// state returns the per-session state, creating it on first use.
func (s *server) state(key string) *sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[key]
	if !ok {
		st = &sessionState{}
		s.sessions[key] = st
	}
	return st
}

// adopt re-keys a reservation to the session the target minted, so the state
// the first read fills in is the state the next read continues from.
func (s *server) adopt(reserved *sessionState, sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sess.Key()
	if _, held := s.sessions[key]; !held {
		s.order = append(s.order, key)
	}
	s.pending--
	delete(s.sessions, stKey(reserved.aliasName))
	s.sessions[key] = reserved
	s.aliases[reserved.aliasName] = key
	reserved.session = sess
}

// openedByUs reports whether this process created a session. A session it only
// found in the catalog does not count.
func (s *server) openedByUs(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[key]
	return ok && st.openedByUs
}

// multiPeer reports whether a tool accepts a peer argument. With one target
// there is nothing to choose, so the argument is absent from the schema.
func (s *server) multiPeer() bool { return len(s.peers) > 1 }

// peerArg reads the peer argument, refusing one when this process serves a
// single target. An empty result is the default target.
func (s *server) peerArg(a args) (string, error) {
	p, err := a.str("peer")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", nil
	}
	if !s.multiPeer() {
		return "", invalidParams("this server serves one target, so it takes no peer argument; " +
			"start it with --allow-peer to serve more")
	}
	for _, known := range s.peers {
		if known == p {
			return p, nil
		}
	}
	return "", invalidParams("peer %q is not served by this process; it serves %s",
		p, strings.Join(s.peerNames(), ", "))
}

func (s *server) peerNames() []string {
	out := make([]string, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, orLocal(p))
	}
	return out
}

// resolve maps the session argument to a session on a served target.
func (s *server) resolve(a args) (Session, error) {
	ref, err := a.str("session")
	if err != nil {
		return Session{}, err
	}
	if strings.TrimSpace(ref) == "" {
		return Session{}, invalidParams("session is required: pass an alias from session_open, " +
			"or a session id")
	}
	peer, err := s.peerArg(a)
	if err != nil {
		return Session{}, err
	}
	return s.backend.Resolve(context.Background(), ref, peer)
}

// open creates a session without attaching to it.
//
// Attaching would take the exclusive write slot, and the first send after that
// would be refused with "session in use", so the process would lock itself out
// of the session it just opened.
func (s *server) open(ctx context.Context, a args) (string, any, error) {
	req := OpenRequest{}
	var err error
	// A name is validated by the alias file, which is where it ends up. Leading
	// and trailing space is trimmed here so a name cannot be half a name.
	if req.Name, err = a.str("name"); err != nil {
		return "", nil, err
	}
	if req.Shell, err = a.str("shell"); err != nil {
		return "", nil, err
	}
	if req.Peer, err = s.peerArg(a); err != nil {
		return "", nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	st, err := s.reserve(req.Name)
	if err != nil {
		return "", nil, err
	}
	// The reserved name is the session's alias, so the backend records the one
	// the model will use to reach it.
	req.Name = st.aliasName

	opened, err := s.backend.Open(ctx, req)
	if err != nil {
		s.dropReserved(req.Name)
		return "", nil, mapError(err, Session{Alias: req.Name})
	}
	s.adopt(st, opened.Session)
	s.logf("session_open alias=%s session=%s peer=%s shell=%q",
		st.aliasName, opened.Session.ID, opened.Session.Peer, req.Shell)

	// The first read shows the prompt. A session that already holds output on
	// the target is trimmed, so the model sees the state of the shell rather
	// than a page of history.
	st.mu.Lock()
	page, rerr := s.readLocked(ctx, st, opened.Session, 0, 0,
		defaultReadWaitMS*time.Millisecond, Wait{}, true)
	st.mu.Unlock()
	if rerr != nil {
		// The session exists and is recorded. Failing to read its first output
		// is not a failure to open it, so the result says so instead of
		// pretending nothing was created.
		s.logf("session_open first read failed: %v", rerr)
		// The read is mapped like any other, so a session that is waiting for
		// approval or that the target closed says what to do about it.
		readErr := mapError(rerr, opened.Session)
		return fmt.Sprintf("opened %s (session %s) on %s, but the first read failed: %s\n%s",
			opened.Session.Label(), opened.Session.ID, orLocal(opened.Session.Peer), readErr,
			opened.HumanAttach), &result{
			Reason:       "read_failed",
			SessionState: stateOf(opened.State),
			Session:      opened.Session.Label(),
			HumanAttach:  opened.HumanAttach,
		}, nil
	}

	text, res := render(opened.Session, page, 0, opened.HumanAttach)
	res.Session = opened.Session.Label()
	return text, res, nil
}

// list returns what the local catalog holds, with one probe read per session to
// find out which are still running.
func (s *server) list(ctx context.Context) (string, any, error) {
	rows, err := s.backend.List(ctx)
	if err != nil {
		return "", nil, mapError(err, Session{})
	}

	out := make([]sessionRow, 0, len(rows))
	var b strings.Builder
	fmt.Fprintf(&b, "%d session(s) in the local catalog.\n", len(rows))

	for _, it := range rows {
		// The catalog cannot know which sessions this process opened, so the
		// answer comes from the state the tools kept. It matters because
		// closeOnExit acts on exactly those.
		openedByUs := s.openedByUs(it.Session.Key())
		row := sessionRow{
			Session:    it.Session.Label(),
			ID:         it.Session.ID,
			Peer:       orLocal(it.Session.Peer),
			Recorded:   it.Recorded,
			OpenedByUs: openedByUs,
			Created:    it.Created,
		}
		// A probe is a read with no wait: one round trip, no parked read. It
		// still goes through the target's approval gate, so on a remote target
		// in pre mode it can come back asking for approval. That is reported and
		// the remaining rows are still listed.
		page, perr := s.probe(ctx, it.Session)
		switch {
		case perr != nil:
			row.State = "unknown"
			row.ProbeError = mapError(perr, it.Session).Error()
		case page.Exited:
			row.State = "exited"
		default:
			row.State = "running"
		}
		out = append(out, row)

		fmt.Fprintf(&b, "- %s (%s) on %s: %s", row.Session, row.ID, row.Peer, row.State)
		if row.OpenedByUs {
			b.WriteString(", opened by this process")
		}
		if row.Recorded != "" && !strings.EqualFold(row.Recorded, row.State) {
			fmt.Fprintf(&b, ", catalog says %s", row.Recorded)
		}
		if row.ProbeError != "" {
			fmt.Fprintf(&b, "\n  probe failed: %s", row.ProbeError)
		}
		b.WriteString("\n")
	}

	s.logf("session_list count=%d", len(out))
	return fence(b.String()) + "\n[tyd: rows are from the local catalog; each state is from a probe read]",
		&result{Output: b.String(), Reason: "catalog", SessionState: "catalog", Sessions: out}, nil
}

// probe asks a session for its state without waiting and without touching the
// cursor this process keeps for it, so listing sessions cannot swallow output.
func (s *server) probe(ctx context.Context, sess Session) (Page, error) {
	st := s.state(sess.Key())
	st.mu.Lock()
	defer st.mu.Unlock()
	return s.backend.Read(ctx, ReadRequest{Session: sess})
}

// send types into a session, then reads what those keystrokes produced.
func (s *server) send(ctx context.Context, a args) (string, any, error) {
	sess, err := s.resolve(a)
	if err != nil {
		return "", nil, err
	}
	raw, err := a.str("data")
	if err != nil {
		return "", nil, err
	}
	if raw == "" {
		return "", nil, invalidParams("data is required: the text or keys to type, " +
			"for example \"ls -la\\n\"")
	}
	escapes, err := a.boolean("escapes", true)
	if err != nil {
		return "", nil, err
	}
	data := []byte(raw)
	if escapes {
		if data, err = strutil.ParseSendData(raw); err != nil {
			return "", nil, invalidParams("data could not be unescaped: %v. "+
				"Escapes are \\n, \\r, \\t, \\xHH and \\\\; set escapes=false to send the characters as they are", err)
		}
	}
	if len(data) == 0 {
		return "", nil, invalidParams("data is empty after unescaping")
	}
	if len(data) > maxSendBytes {
		return "", nil, invalidParams("data is %d bytes, over the %d byte limit for one send. "+
			"Split it into several sends of at most %d bytes", len(data), maxSendBytes, maxSendBytes)
	}

	w, err := waitArg(a["wait"])
	if err != nil {
		return "", nil, err
	}
	if w.WaitMS == 0 {
		w.WaitMS = defaultSendWaitMS
	}
	if w.WaitMS > maxWaitMS {
		return "", nil, invalidParams("wait_ms is %d, over the %d ms a read may be parked on a target",
			w.WaitMS, maxWaitMS)
	}
	// A match is the caller's own condition. Without one the read waits for the
	// output to go quiet, so a model that only typed a command still gets that
	// command's output back.
	if w.Match == "" && w.IdleMS == 0 && w.MaxBytes == 0 {
		w.IdleMS = defaultSendIdleMS
	}

	st := s.state(sess.Key())
	st.mu.Lock()
	defer st.mu.Unlock()

	sent, serr := s.backend.Send(ctx, sess, data)
	s.logf("session_send session=%s bytes=%d written=%d", sess.ID, len(data), sent.Written)
	if serr != nil {
		// A send that stopped part way reports how much landed. Without that
		// number a model resends the whole thing and types it twice.
		return "", nil, withWritten(mapError(serr, sess), sent.Written, len(data))
	}

	// Reading from the position the send reported before it wrote means this
	// result holds what these keystrokes produced, not what was on screen
	// before them.
	page, rerr := s.readLocked(ctx, st, sess, sent.Cursor, sent.Epoch,
		time.Duration(w.WaitMS)*time.Millisecond, w, true)
	if rerr != nil {
		// The bytes are in. Losing the output is not a failed send, so the
		// result says what landed and lets the model read on.
		written := sent.Written
		return fmt.Sprintf("sent %d bytes to %s, but the read that followed failed: %v\n"+
				"the keystrokes landed; read the session to see what they produced", written, sess.Label(), rerr),
			&result{
				Reason:       "read_failed",
				SessionState: stateOf(sent.State),
				Cursor:       sent.Cursor,
				Written:      &written,
				Session:      sess.Label(),
			}, nil
	}

	text, res := render(sess, page, sent.Cursor, "")
	written := sent.Written
	res.Written = &written
	res.Session = sess.Label()
	return text, res, nil
}

// read pulls output from a session, continuing from where the last read ended.
func (s *server) read(ctx context.Context, a args) (string, any, error) {
	sess, err := s.resolve(a)
	if err != nil {
		return "", nil, err
	}
	w, err := waitArg(a["wait"])
	if err != nil {
		return "", nil, err
	}
	explicit, hasCursor, err := a.uint("cursor")
	if err != nil {
		return "", nil, err
	}
	maxBytes, hasMax, err := a.uint("max_bytes")
	if err != nil {
		return "", nil, err
	}
	if hasMax {
		if maxBytes == 0 {
			return "", nil, invalidParams("max_bytes must be at least 1")
		}
		if maxBytes > maxResultBytes {
			return "", nil, invalidParams("max_bytes is %d, over the %d byte limit for one page",
				maxBytes, maxResultBytes)
		}
		// A cap on the page is a wake-up rule to the target, which is how the
		// daemon expresses it. Without a condition, applying it here would
		// return a page the caller did not ask to stop at.
		if !w.Any() {
			w.MaxBytes = uint32(maxBytes)
		}
	}
	// A read without a condition still gets a short wait, so a shell that has
	// just printed something is not reported as silent.
	if w.WaitMS == 0 {
		w.WaitMS = defaultReadWaitMS
	}
	if w.WaitMS > maxWaitMS {
		return "", nil, invalidParams("wait_ms is %d, over the %d ms a read may be parked on a target",
			w.WaitMS, maxWaitMS)
	}

	key := sess.Key()
	st := s.state(key)
	st.mu.Lock()
	defer st.mu.Unlock()

	// An explicit cursor is a re-read of one stretch: it does not move the
	// cursor this process keeps, so a paged read can be repeated.
	cursor, epoch := st.cursor, st.epoch
	if hasCursor {
		cursor, epoch = explicit, 0
	}

	page, rerr := s.readLocked(ctx, st, sess, cursor, epoch,
		time.Duration(w.WaitMS)*time.Millisecond, w, !hasCursor)
	if rerr != nil {
		return "", nil, mapError(rerr, sess)
	}

	text, res := render(sess, page, cursor, "")
	res.Session = sess.Label()
	return text, res, nil
}

// interrupt stops whatever the session is running, then reports what the shell
// said about it.
func (s *server) interrupt(ctx context.Context, a args) (string, any, error) {
	sess, err := s.resolve(a)
	if err != nil {
		return "", nil, err
	}
	st := s.state(sess.Key())
	st.mu.Lock()
	defer st.mu.Unlock()

	// The send is under the lock as well. A read of the same session would
	// otherwise hand its page out after the interrupt, and the model would read
	// output from before the command it just stopped.
	sent, serr := s.backend.Send(ctx, sess, []byte{0x03})
	if serr != nil {
		return "", nil, withWritten(mapError(serr, sess), sent.Written, 1)
	}
	s.logf("session_interrupt session=%s written=%d", sess.ID, sent.Written)

	w := Wait{IdleMS: interruptIdleMS}
	page, rerr := s.readLocked(ctx, st, sess, sent.Cursor, sent.Epoch,
		interruptWaitMS*time.Millisecond, w, true)
	if rerr != nil {
		written := sent.Written
		return fmt.Sprintf("sent the interrupt to %s, but the read that followed failed: %v",
			sess.Label(), rerr), &result{
			Reason:       "read_failed",
			SessionState: stateOf(sent.State),
			Cursor:       sent.Cursor,
			Written:      &written,
			Session:      sess.Label(),
		}, nil
	}
	text, res := render(sess, page, sent.Cursor, "")
	res.Session = sess.Label()
	return text, res, nil
}

// close ends a session.
func (s *server) close(ctx context.Context, a args) (string, any, error) {
	sess, err := s.resolve(a)
	if err != nil {
		return "", nil, err
	}
	if err := s.backend.Close(ctx, sess); err != nil {
		return "", nil, mapError(err, sess)
	}
	s.forget(sess.Key())
	s.logf("session_close session=%s", sess.ID)
	return fmt.Sprintf("closed %s (session %s).", sess.Label(), sess.ID), &result{
		Reason: "closed", SessionState: "closed", Session: sess.Label(),
	}, nil
}

// readLocked pulls one page and advances the saved cursor. The caller holds the
// per-session lock.
//
// advance is false for a read that must not move the saved position: an
// explicit re-read. The first contact is decided by the state rather than by the
// caller, so no path can trim the output of a session this process has already
// read.
func (s *server) readLocked(ctx context.Context, st *sessionState, sess Session,
	cursor, epoch uint64, wait time.Duration, w Wait, advance bool) (Page, error) {

	report := progressOf(ctx)
	stop := make(chan struct{})
	if report != nil {
		go reportWhileWaiting(report, stop)
	}
	page, err := s.backend.Read(ctx, ReadRequest{
		Session:  sess,
		Cursor:   cursor,
		Epoch:    epoch,
		Wait:     wait,
		Cond:     w,
		Progress: report,
	})
	close(stop)
	if err != nil {
		return Page{}, err
	}

	// The first read of a session has no position to continue from. It is
	// trimmed instead of started at the beginning of the log.
	if !st.touched {
		page = trimFirstContact(page)
		st.touched = true
	}
	if advance {
		// A read that adopted a new cursor has to be remembered even when it
		// returned no bytes, or the next read asks for a position the target no
		// longer has.
		st.cursor, st.epoch = page.CursorNext, page.Epoch
	}
	return page, nil
}

// reserve claims an alias and a session slot, or refuses. Picking the name and
// claiming it happen under one lock, so two concurrent opens cannot both take
// agent-1.
//
// The cap is checked here rather than after the create, so a refused open leaves
// nothing behind on the target.
func (s *server) reserve(name string) (*sessionState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		for i := 1; ; i++ {
			candidate := "agent-" + strconv.Itoa(i)
			if _, used := s.aliases[candidate]; !used {
				name = candidate
				break
			}
		}
	}
	if _, used := s.aliases[name]; used {
		return nil, invalidParams("alias %q is already used by a session this process opened; "+
			"pass a different name", name)
	}
	if len(s.order)+s.pending >= s.maxSessions {
		return nil, toolErrf("this process already holds %d sessions, its limit. "+
			"Call session_close on one you no longer need, or start the server with a higher --max-sessions.",
			s.maxSessions)
	}
	st := &sessionState{aliasName: name, openedByUs: true}
	s.aliases[name] = ""
	s.sessions[stKey(name)] = st
	s.pending++
	return st, nil
}

// dropReserved releases a reservation for a session that was never created.
func (s *server) dropReserved(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
	delete(s.sessions, stKey(name))
	if key, ok := s.aliases[name]; ok && key == "" {
		delete(s.aliases, name)
	}
}

// stKey namespaces a reservation that has no session id yet.
func stKey(name string) string { return "\x00alias:" + name }

func (s *server) forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
	for alias, k := range s.aliases {
		if k == key {
			delete(s.aliases, alias)
		}
	}
	out := s.order[:0]
	for _, k := range s.order {
		if k != key {
			out = append(out, k)
		}
	}
	s.order = out
}

func (s *server) logf(format string, args ...any) { s.log.logf(format, args...) }

func stateOf(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return strings.ToLower(s)
}

func orLocal(peer string) string {
	if peer == "" {
		return "local"
	}
	return peer
}
