package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	"tyd/internal/alias"
	"tyd/internal/catalog"
	"tyd/internal/client"
	"tyd/internal/live"
	"tyd/internal/mcp"
	"tyd/internal/peers"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// mcpTarget is one machine this server drives. A process serves exactly one
// target unless it was started with --allow-peer, because a model that can
// choose the machine can also reach the one nobody meant to offer.
type mcpTarget struct {
	// label is what a tool call names the target by. The local daemon's label
	// is mcpLocalRef, so a target is never nameless: "the model may be typing
	// into the machine you are sitting at" is the one mistake this command must
	// not make quietly.
	label string
	// peerID is the paired peer behind the label, empty for the local daemon.
	peerID string
	// nickname is what a person types for the peer, used in the attach command.
	nickname string
}

// mcpLocalRef is the name the daemon on this machine answers to on the command
// line. It is a word rather than an empty string so that a target is always
// named, in the startup line and in every tool result. It is reserved: a peer
// may not hold it, and it is resolved before any peer, so an older peers.json
// that has one cannot take this name away from the machine it names.
const mcpLocalRef = peers.ReservedNickname

// mcpBackend drives real daemons.
//
// An endpoint is resolved per target and cached: it carries a certificate pin
// and a dial timeout that must stay the same across the read and the send that
// follow it.
type mcpBackend struct {
	opts    options
	key     ed25519.PrivateKey
	targets []mcpTarget

	mu  sync.Mutex
	eps map[string]client.Endpoint
}

func newMCPBackend(opts options, key ed25519.PrivateKey, targets []mcpTarget) *mcpBackend {
	return &mcpBackend{opts: opts, key: key, targets: targets, eps: map[string]client.Endpoint{}}
}

// target maps a tool call's peer argument to a target. An empty label is the
// first target, which is the one --peer named, or the only outbound peer.
func (b *mcpBackend) target(label string) (mcpTarget, error) {
	if label == "" {
		return b.targets[0], nil
	}
	for _, t := range b.targets {
		if t.label == label {
			return t, nil
		}
	}
	return mcpTarget{}, fmt.Errorf("peer %q is not served by this process", label)
}

func (b *mcpBackend) endpointFor(t mcpTarget) (client.Endpoint, error) {
	b.mu.Lock()
	ep, ok := b.eps[t.label]
	b.mu.Unlock()
	if ok {
		return ep, nil
	}
	if t.peerID == "" {
		ep = client.Endpoint{Kind: transport.KindUnix, Address: b.opts.socket}
	} else {
		o := b.opts
		// recent.json is not consulted: it records the machine a person last
		// typed, and a server that followed it would drive a different target
		// than the one it was started for.
		o.peer = t.peerID
		resolved, _, err := endpoint(o)
		if err != nil {
			return client.Endpoint{}, err
		}
		ep = resolved
	}
	b.mu.Lock()
	b.eps[t.label] = ep
	b.mu.Unlock()
	return ep, nil
}

func (b *mcpBackend) Open(_ context.Context, req mcp.OpenRequest) (mcp.Opened, error) {
	t, err := b.target(req.Peer)
	if err != nil {
		return mcp.Opened{}, err
	}
	ep, err := b.endpointFor(t)
	if err != nil {
		return mcp.Opened{}, err
	}

	// client.Create creates without attaching. Attaching here would take the
	// exclusive write slot, and the first send after that would be refused.
	info, err := client.Create(ep, b.key, client.CreateOpts{Shell: req.Shell})
	if err != nil {
		return mcp.Opened{}, err
	}
	rememberSession(b.opts, catalog.FromInfo(info, t.peerID, ep.Address, ep.CertFP,
		string(ep.Kind), ep.Candidates))

	// Record the alias so a person can reach the session from a terminal. The
	// model is the writer, but a human still needs a way in.
	if req.Name != "" {
		adoc, err := alias.Load(b.opts.aliases)
		if err != nil {
			return mcp.Opened{}, err
		}
		if err := adoc.Set(req.Name, info.ID, t.peerID); err != nil {
			return mcp.Opened{}, err
		}
		if err := alias.Save(b.opts.aliases, adoc); err != nil {
			return mcp.Opened{}, err
		}
	}
	return mcp.Opened{
		Session:     mcp.Session{ID: info.ID, Alias: req.Name, Peer: t.label},
		HumanAttach: humanAttach(t, req.Name, info.ID),
		State:       info.State,
	}, nil
}

// humanAttachFor is humanAttach for a session this backend is already driving.
func (b *mcpBackend) humanAttachFor(sid string) string {
	t, err := b.target("")
	if err != nil {
		return ""
	}
	return humanAttach(t, aliasNameFor(b.opts, sid), sid)
}

// humanAttach is the command a person runs to take a session over. It is returned
// in the tool result so a model can hand it to the user instead of making them
// work out the peer syntax.
func humanAttach(t mcpTarget, name, id string) string {
	ref := name
	if ref == "" {
		ref = id
	}
	if t.nickname == "" {
		return "tyd session attach " + ref
	}
	return fmt.Sprintf("tyd %s.%s", ref, t.nickname)
}

func (b *mcpBackend) Resolve(_ context.Context, ref, peerLabel string) (mcp.Session, error) {
	t, err := b.target(peerLabel)
	if err != nil {
		return mcp.Session{}, err
	}
	sid, err := resolveSessionRef(b.opts, ref)
	if err != nil {
		return mcp.Session{}, err
	}
	// The session is then driven on the target that was chosen, so the two have
	// to agree. Without this check a name that exists on two machines could send
	// a model's keystrokes to the wrong one of them.
	if err := b.checkTarget(t, sid); err != nil {
		return mcp.Session{}, err
	}
	return mcp.Session{ID: sid, Alias: aliasNameFor(b.opts, sid), Peer: t.label}, nil
}

// checkTarget refuses a session that the catalog records against another
// machine. A session with no peer in the catalog is local.
func (b *mcpBackend) checkTarget(t mcpTarget, sid string) error {
	cat := loadLocalCatalog(b.opts)
	rec, ok := cat.Get(sid)
	if !ok {
		// The catalog is a local file and a session may be on a target this
		// process has never listed. The target itself is the authority.
		return nil
	}
	if rec.PeerID == t.peerID {
		return nil
	}
	where := b.labelForRecord(rec)
	return fmt.Errorf("session %s is on %s, not %s. Read the session from the target it belongs to",
		mcp.Session{ID: sid, Alias: aliasNameFor(b.opts, sid)}.Label(),
		orLocalLabel(where), orLocalLabel(t.label))
}

func orLocalLabel(label string) string {
	if label == "" {
		return "this machine"
	}
	return label
}

func (b *mcpBackend) List(context.Context) ([]mcp.Listed, error) {
	cat := loadLocalCatalog(b.opts)
	records := cat.List()
	adoc, _ := alias.Load(b.opts.aliases)
	arch := loadArchive(b.opts)

	out := make([]mcp.Listed, 0, len(records))
	for _, rec := range records {
		// A session nobody has touched for --archive-ttl stays out of this list,
		// the same as it stays out of `tyd session list`. The tool has no way to
		// ask for the hidden ones, so the mark is cleared by using the session
		// rather than by looking at it.
		if arch.SessionArchived(rec.ID) {
			continue
		}
		out = append(out, mcp.Listed{
			Session:  mcp.Session{ID: rec.ID, Alias: aliasNameOf(adoc, rec.ID), Peer: b.labelForRecord(rec)},
			Recorded: rec.State,
			Created:  catalog.CreatedDisplay(rec),
			// The tool layer runs the probe read, so no state is claimed here.
		})
	}
	return out, nil
}

func (b *mcpBackend) labelForRecord(rec catalog.Record) string {
	for _, t := range b.targets {
		if t.peerID == rec.PeerID {
			return t.label
		}
	}
	if rec.PeerID == "" && len(b.targets) > 0 {
		return b.targets[0].label
	}
	// A session recorded against a peer this process does not serve. It is
	// listed so the model can see it exists, and a call naming it is refused
	// with the reason.
	return rec.PeerID
}

func aliasNameFor(opts options, sid string) string {
	adoc, err := alias.Load(opts.aliases)
	if err != nil {
		return ""
	}
	return aliasNameOf(adoc, sid)
}

func aliasNameOf(adoc *alias.File, sid string) string {
	if adoc == nil {
		return ""
	}
	return adoc.NameFor(sid)
}

func (b *mcpBackend) Send(ctx context.Context, s mcp.Session, data []byte) (mcp.Sent, error) {
	t, err := b.target(s.Peer)
	if err != nil {
		return mcp.Sent{}, err
	}
	ep, err := b.endpointFor(t)
	if err != nil {
		return mcp.Sent{}, err
	}
	// The context is passed so a cancelled send closes the connection and the
	// daemon aborts the write, rather than the keystrokes landing after the model
	// was told they did not.
	rep, err := client.SendContext(ctx, ep, b.key, s.ID, data)
	if err != nil {
		return mcp.Sent{}, err
	}
	b.markUsed(t, s.ID)
	return mcp.Sent{
		Written:      rep.Written,
		WrittenKnown: rep.Reported,
		Cursor:       rep.Cursor,
		Epoch:        rep.Epoch,
		HumanAttach:  b.humanAttachFor(s.ID),
	}, nil
}

// markUsed records that a session was driven on a named machine.
//
// It is the same bookkeeping the CLI does after a successful attach, read or
// send, and for the same reason: the session stops being something nobody has
// touched. A session that was archived out of the list comes back, because a
// model driving it plainly means it is in use, and hiding a session someone is
// working in is how a person stops trusting the list.
func (b *mcpBackend) markUsed(t mcpTarget, sid string) {
	touchSession(b.opts, sid)
	markUsed(b.opts, t.peerID, sid)
}

func (b *mcpBackend) Read(ctx context.Context, req mcp.ReadRequest) (mcp.Page, error) {
	t, err := b.target(req.Session.Peer)
	if err != nil {
		return mcp.Page{}, err
	}
	ep, err := b.endpointFor(t)
	if err != nil {
		return mcp.Page{}, err
	}
	cond := live.ReadConditions{
		IdleMS:   req.Cond.IdleMS,
		Match:    req.Cond.Match,
		MaxBytes: req.Cond.MaxBytes,
	}

	// ReadContext closes the connection when ctx ends, which is what lets the
	// daemon's read give up instead of holding its slot until wait_ms.
	frame, err := client.ReadContext(ctx, ep, b.key, req.Session.ID, req.Cursor, req.Epoch, req.Wait, cond)
	if err != nil {
		return mcp.Page{}, err
	}
	b.markUsed(t, req.Session.ID)
	return mcp.Page{
		Data:        frame.Data,
		CursorNext:  frame.CursorNext,
		Dropped:     frame.Dropped,
		Epoch:       frame.Epoch,
		CursorAhead: frame.CursorAhead,
		Exited:      frame.Exited,
		Reason:      frame.Reason,
		HumanAttach: b.humanAttachFor(req.Session.ID),
	}, nil
}

func (b *mcpBackend) Close(_ context.Context, s mcp.Session) error {
	t, err := b.target(s.Peer)
	if err != nil {
		return err
	}
	ep, err := b.endpointFor(t)
	if err != nil {
		return err
	}
	if err := client.CloseSession(ep, b.key, s.ID); err != nil {
		return err
	}
	if rec, ok := loadLocalCatalog(b.opts).Get(s.ID); ok {
		rec.State = string(session.StateClosed)
		rememberSession(b.opts, rec)
	}
	return nil
}

// compile-time check that the real backend satisfies the tool contract.
var _ mcp.Backend = (*mcpBackend)(nil)
