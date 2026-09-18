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
| After successful accept | Pairing is **permanent** until an explicit peer/pairing revoke |

### Accept

- Client (C) runs `tyd accept <invite>` (optional peer nickname via `--as`).
- Direction for a given pair is **unidirectional**: after C accepts S's invite,
  C may request TTY session ops on S.
- Roles are symmetric across different pairs: C may also `register` and invite others.

### Approval modes (declared at register / on server)

| Mode | Behavior |
|------|----------|
| **pre** (pre-approval) | Every remote (non-unix: TLS or QUIC) create, attach, and watch waits for a local `approve`; unix bypasses |
| **post** (post-approval) | Auto-approve like full; control events are audited (no TTY content) |
| **full** (full approval) | **Default.** Session records only; no per-session review |

Applied by the daemon from `peers.json`. `tyd approval <mode>` changes it in
place (CP + local file) and keeps the daemon id and pairings; re-registering is
not required and `--force` remains the only path that drops peers.

Approvals under **pre** are **one-shot**: approving a create also covers the
attach that immediately follows, and every later reattach is reviewed again.
Pending requests and unused approvals expire after 10 minutes, so a peer never
holds standing access.

### Audit log (independent of approval mode)

- `tyd up --audit-log PATH` appends JSON Lines (`0600`), suggested `~/.tyd/audit.log`
- Events: create, create_pending, approve, reject, attach, attach_pending, detach, close, idle_close, denied
- Records are metadata only (session id, principal, peer id, transport, remote addr, capability, timestamps); never TTY content
- Audit stays local: nothing is sent to the CP
- Without the flag, **post** writes the same records to stderr and other modes write nothing

### Local state durability

- All state files (`peers.json`, `trusted.json`, `aliases.json`, `sessions.json`,
  `recent.json`, identity, live `meta.json`) are written temp-file-then-rename;
  a failed write must leave the previous file intact
- The daemon holds registration and peers **in memory**; `peers.json` is a cache
  - Maintenance loop never reads the file to do its work; it reloads only when the file still parses and memory has nothing unsaved
  - Write failures warn once, are retried each tick, and never disable CP sync, endpoint publishing, or peer trust
- Startup with an unparsable `peers.json`: rename to `peers.json.corrupt.<ts>`,
  then recover registration + peers from the CP by public key
  - Recovery states **no** approval mode; the CP keeps the recorded one (`POST /v1/register` with an empty `approval_mode` on a known key preserves it)
  - CP unreachable ⇒ run local-only and point the operator at `tyd doctor --fix`
- Audit write failure: warn once, keep serving
- `tyd doctor` checks state files, free space, and writability; `--fix` rebuilds `peers.json`

### Session idle timeout

- `tyd up --session-idle-timeout D` closes sessions unattended for longer than `D`
- **Default off**; idle starts at the last detach and resets on attach
- `PENDING` sessions are never reaped

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

## Client UX

- `tyd alias` is for **sessions** (not peers). Stored client-side in `~/.tyd/aliases.json`.
- Client session catalog: `~/.tyd/sessions.json` (written on create; `session list` is file-only).
- Peer targeting for dialing commands (`session create` / `attach` / `watch` / `close`):
  - `--peer <cp-id>` or peer nickname set at accept (`--as`)
  - If omitted: recent peer from `recent.json` if still known; else 1 outbound → use it;
    0 outbound → local unix; many outbound → error (no interactive prompt).
  - Attach prefers dial address stored in the catalog when present (skips CP).
- `session list` **ignores** `--peer` / CP / daemon — merges catalog + aliases + recent.
- Session id targeting: pass id, pass alias, or omit → most recent session id.
- `status` shows CP registration + peers + recent + aliases + live connections.

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
4. **Invite / peer revoke** — Unused invites expire at TTL or via `tyd invite revoke`.
   Established pairs are revoked with `tyd revoke <peer>` (either side).

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
- Integration test: CP + pair + publish + remote session **create** over TLS (list is client-local)

## Explicitly out of Step 1–5

- Remote mesh beyond loopback advertise / data-listen
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

## Step 4 deliverables

- `tyd alias [<session_id>] <name>` / `tyd alias list` / `tyd alias rm <name>` → `~/.tyd/aliases.json`
- Session commands resolve alias names; omitting id uses `recent.json` session placeholder
- `session list` shows ALIAS / PEER columns from the **client catalog** (`sessions.json`)
- `tyd status` prints Control Panel / Peers / Recent / Session aliases / Connections
- Help tips show recent session as placeholder when available
- Docs (roadmap, guide, README) updated

### Client catalog + attach UX (post Step 4)

- `~/.tyd/sessions.json`: create records id + dial addr; list is local-only
- `session create` attaches by default (`--detach` for scripts)
- `tyd up` reuses local registration; restores missing CP daemon via `/v1/restore`
- `tyd register` when already registered requires `--force` or TTY confirm (invalidates peers)
- Attach/watch: missing session → not found; present without cap → permission denied

## Step 5 deliverables

- CP: `RevokeInvite`, `RevokePeer` (either side); prune used/expired invites; JSON body size limit
- HTTP: `POST /v1/invites/revoke`, `DELETE /v1/daemons/{id}/peers/{peerID}?public_key=`
- CLI: `tyd invite`, `tyd invite revoke <token>`, `tyd revoke <peer>`
- Local `peers.json` replace-from-CP on sync so revokes propagate; drop inbound peer from in-memory trust
- Tests: invite revoke, peer revoke both sides, own-invite reject, AuthN fails after revoke
