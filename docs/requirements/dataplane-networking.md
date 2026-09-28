# Data-plane networking after pairing

> Historical requirements document (REQ-110) for the peer data plane. For how it
> behaves today, read [operations.md](../operations.md); for implementation
> status see [roadmap.md](../roadmap.md).

Product decision (REQ-110): after Control Panel pairing, peers form a **1:1 data plane**
inside tyd. Keys reuse the existing Ed25519 pair identity.

## Phases

| Phase | Transport | Status |
|-------|-----------|--------|
| **1** | **QUIC direct** | Done — clients try published candidates in order, then use the Phase 3 relay if every candidate fails |
| **2** | WireGuard | Planned |
| **3** | Relay | MVP done — WebSocket on CP `/relay` (+ optional `tyd-relay`); direct first, relay as fallback |

## Hard rules

- Session / TTY bytes **never** go through Control Panel.
- The relay is a separate data path: the CP may host `/relay`, but it keeps only
  pairing metadata and never sees or stores session bytes.
- Topology is **1:1** per pair (not a full mesh yet).

## Lifecycle

| Command | Role |
|---------|------|
| `tyd up` | Daemon; keep CP registration/peers in sync; listen + publish data-plane candidates; offer on `--relay` |
| `tyd register` / `tyd accept` | Establish pair; once both sides `up`, DP uses published candidates (no manual `--advertise` required for LAN/same-host) |
| `tyd-relay` / CP `/relay` | Blind WebSocket splice (TLS at edge); default URL `https://app.getfda.dev/relay` |

## Phase 1 behavior

1. When registered, `tyd up --data-listen auto` listens **QUIC** on `0.0.0.0:0` (all interfaces).
2. Publishes to CP: primary `addr`, `cert_fp`, `transport=quic`, plus `candidates` (interface IPs + optional `--advertise` + loopback for local tests).
3. **Create** (and attach/watch/close when the catalog has no dial addr yet) resolve the peer endpoint from CP and **try candidates in order** until dial + AuthN succeed.
4. Successful **create** records the dial target in the client catalog (`~/.tyd/sessions.json`); later attach prefers that address.
5. **`session list` does not use CP or the data plane** — it is a local catalog read.
6. If every direct candidate fails → **relay fallback** (Phase 3 MVP) when `--relay` is not `off`.

## Phase 3 MVP (relay)

Tailcat-like behavior without DERP/WireGuard:

1. Prefer CP `/relay` (WebSocket) at the Control Panel origin; optional dedicated `tyd-relay` (compose `relay`) behind TLS.
2. Server: `tyd up` keeps an outbound **offer** on the relay keyed by daemon id.
3. Client: after direct QUIC candidates fail (or CP has no endpoint), dials the relay with the peer id over **WebSocket**; relay notifies the server, splices the two streams.
4. Existing Ed25519 AuthN + session frames run end-to-end over the splice (relay is blind to TTY).
5. `--relay URL` overrides the default; `--relay off` disables fallback and offering.

## Phase 4 (relay redundancy)

The relay was a single point of failure: one process, in-memory state, one URL.
Phase 4 is split, because "the relay died" and "a live session died" need
different mechanisms and conflating them hides the hard part.

### 4a. Several relays (done)

`--relay` takes a comma-separated list. `tyd up` offers on every entry
concurrently and independently; clients walk the list in order on fallback. The
relays share no state — an offer lives in the process it registered with and a
ticket is only claimed on that same process — so there is nothing to cluster and
**several replicas behind a round-robin proxy will break the handshake**
(`unknown ticket`), not provide redundancy. Each relay needs its own hostname.

This covers a dead relay *process*. It does not cover a live session: bytes of a
spliced session flow through that one process, so killing it kills the session.
Forwarding tickets between relays (a mesh) would not help either — it makes the
*dial entry point* redundant, not the byte path.

### 4b. Surviving live sessions (in progress)

Only moving the data path off the relay achieves that, in three steps.

**4b.1. Cross-announce observed addresses (done).** The relay tells each side the
address it observed for the other: `Observed` rides on `TypeIncoming` (relay →
server) and on `TypeOK` (relay → client). No new message type and no handshake
reordering is possible or needed — after `TypeOK` the connection is a raw byte
pipe, so the announcement has to travel on frames that already cross. The field
is optional and additive, so a new daemon still talks to an old relay and vice
versa.

`RemoteAddr` on those connections is NAT ground truth: it is the post-NAT source
the relay actually received. That is precisely what the self-reported interface
IPs published to the Control Panel are not, and why hard-NAT peers need the
splice at all.

Both sides record the address and **do not dial it**. The point is measurement:
until it is known whether an observed address would really connect, preferring
direct is a guess. If most observed addresses turn out to be unreachable, a
direct-first switch would be a connectivity regression, and the data says so
before it ships. Clients and servers log the value (`--verbose` on the client).

**4b.2. Direct-first with splice fallback (planned).** Prefer direct QUIC once an
observed address is known, and fall back to the splice automatically and without
user-visible error when the direct attempt fails. The fallback must stay:
published candidates are usually unreachable behind NAT, so removing it would
*reduce* connectivity.

**4b.3. Reconnect and re-attach (planned).** On transport loss, re-dial (direct
or another relay) and re-attach the same session id. The server already lets a
new connection re-attach a live session, and the PTY is untouched by a transport
drop, so the shell is never lost.

## Out of Phase 1 / this MVP

- STUN / ICE hole punching across strict NATs
- WireGuard
- Upgrading an active relay path to direct mid-session
- Relays sharing offers or tickets across processes (deliberately: see 4a)
