# Control plane pairing (requirements)

Authoritative product requirements for tyd peer pairing via a Control Panel (CP).
Implementation is phased; see [docs/roadmap.md](../roadmap.md).

## Goals

- CP **only** does pairing: exchange peer public keys between ends.
- CP **must not** record or store tyd customer session / TTY data.
- After pairing, peers use exchanged keys to **self-form the data network**.
- The data plane does **not** go through CP.

## Platform URL

| Context | URL |
|---------|-----|
| Default production | `https://app.getfda.dev` |
| Local / tests | HTTP base URL of an in-repo CP (`go run ./cmd/controlpanel`) |
| Override | CLI / daemon flag `--platform <url>` |

Self-hosted CP is supported via `--platform`. A registered daemon is addressed as
`app.getfda.dev/<id>` (or `<platform-host>/<id>` when self-hosted).

## Register / Accept

### Register

- `tyd register` registers the **current daemon identity** with CP.
- Multiple users on one machine ⇒ each distinct identity / data dir is an
  **independent** CP registration.
- CP **allocates** the public id and returns it to the server side (S).
- S then **creates an invite** (token) for a peer to accept.

### Invite

| Rule | Value |
|------|--------|
| Invite TTL | **10 minutes** |
| Unused invite after TTL | Expired (treat as invite revoke for unused invites) |
| After successful accept | Pairing is **permanent** until an explicit peer/pairing revoke (later step) |

### Accept

- Client (C) runs `tyd accept <invite>` (optional peer nickname via `--as`).
- Direction for a given pair is **unidirectional**: after C accepts S's invite,
  C may request TTY session ops on S.
- Roles are symmetric across different pairs: C may also `register` and invite others.

### Approval modes (declared at register / on server)

| Mode | Behavior |
|------|----------|
| **pre** (pre-approval) | TLS (data-plane) creates enter `PENDING` until local operator `approve`; unix creates bypass |
| **post** (post-approval) | Auto-approve like full; on session close emit local audit log (no TTY content) |
| **full** (full approval) | **Default.** Session records only; no per-session review |

Enforcement is Step 3 (declared at register; applied by the daemon from `peers.json`).

## Identity / daemon

- No manual `keygen` required for normal use — identity is created **implicitly**
  on first `up` / `register` / `accept` (optional `keygen` remains for explicit setup).
- Local **unix socket** remains for local CLI ↔ daemon (`~/.tyd/tyd.sock`).
- Default: **do not** open TCP listen (`127.0.0.1:61211` is **off** by default).
- Primary daemon command: **`tyd up`** (`serve` may remain as alias / deprecated hint).
- Default platform: `app.getfda.dev` unless `--platform`.
- Daemon maintains contact with CP for pairing / presence / signaling and is
  registered as `app.getfda.dev/<id>` (full CP heartbeat is later; Step 1 is
  register / accept / local peer persistence).

## Client UX (later steps; recorded here)

- `tyd alias` is for **sessions** (not peers).
- Peer targeting for `session create` etc.:
  - `--peer <cp-id>` or peer nickname set at accept (`--as`)
  - If omitted: 0 peers → error; 1 peer → use it; many → use peer of
    **most recent session** as default (no interactive prompt).
- `status` should reflect CP connection + peers (OK to evolve).

## Privacy boundary (hard)

CP may store **pairing metadata only**:

- Public ids
- Peer public keys
- Invite tokens / expiry
- Approval mode declared at register
- Pairing timestamps / nicknames

CP must **not** store or log:

- TTY bytes / session content
- Session attach transcripts
- Customer shell output

## Open decisions (Amy defaults for connectivity MVP)

These guide Step 2+; not implemented in Step 1.

1. **Ephemeral signaling via CP** — CP may help peers exchange dial endpoints
   (addresses, temporary connection hints) so they can establish a P2P / direct
   path. Signaling records are ephemeral; CP does not persist customer TTY.
2. **Data frames never through CP** — After keys are exchanged, session I/O and
   auth between peers use the data plane only.
3. **Peer AuthN** — Paired peers authenticate with the exchanged Ed25519 public
   keys (trust entries derived from `peers.json` / local store).
4. **Invite revoke** — Unused invites expire at TTL; established pairs are
   revoked only via an explicit revoke command (Step 5).

## Step 1 deliverables

- This requirements doc + roadmap phasing
- Minimal in-repo CP service (local runnable, testable)
- `tyd up` / `register` / `accept` skeleton, auto-identity, TCP listen off by default
- Persist paired peer public keys locally
- Tests for invite expiry, key exchange, auto-identity, listen default

## Step 2 deliverables

- Ephemeral CP endpoint signaling (`PUT`/`GET /v1/daemons/{id}/endpoint`); default TTL ~90s; overwrite; expired ⇒ 404
- `cpclient.PublishEndpoint` / `GetEndpoint`
- Data-plane TLS on `tyd up` via `--data-listen auto|off|HOST:PORT` and `--advertise HOST`
- Peer pubs from CP sync → in-memory trust (`EnsurePeer` with `list`+`create`); dynamic Add is enough for Step 2
- Client dials peer by cert fingerprint (`DialTLSFingerprint`); session I/O never through CP
- `--peer <id|nickname>`; recent peer file `~/.tyd/recent.json`; single-outbound default; zero outbound → local unix
- Integration test: CP + pair + publish + remote session create/list over TLS

## Explicitly out of Step 1–3 (later steps)

- Remote mesh beyond loopback advertise / data-listen
- Session alias command
- Peer revoke
- Production deployment of `app.getfda.dev` (local CP is enough for tests)
- NAT traversal / STUN

## Step 3 deliverables

- Daemon reads `Registration.ApprovalMode` into `server.Config` (default `full`)
- **pre** + TLS create → `PENDING` (no PTY); attach/write/resize/signal denied; unix `approve` starts PTY → `DETACHED`; `reject` / close removes pending
- **pre** + unix create → no pending (bypass)
- **post**: create as full; on CLOSED emit audit line (principal, session id, created_at, closed_at, peer id if known); no TTY in log; audit stays local (not sent to CP)
- **full**: create works without approve
- Protocol: `approve` / `reject` (unix only); CLI `tyd session approve|reject`
- List shows `PENDING`; alive-first sort treats PENDING as alive
- Tests for pre/post/full and unix bypass under pre
