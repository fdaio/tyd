# Roadmap: what exists, what does not

## Local foundations

### Step 1 — Persistent local PTY

- Single binary `tyd`
- `tyd up` (alias `serve`) / `session create|list|attach|watch|close` / `status` / `keygen`
- PTY + shell; resize; SIGINT-style signals via PTY control bytes
- Client disconnect / detach leaves the shell running; reattach works
- A shell that exits (`exit`, Ctrl-D, crash, kill) does not close the session: it
  becomes `EXITED`, stays attachable, and the next attach replays the recorded
  output before starting a new shell
- One **live-agent process per session** (`~/.tyd/live/<id>/`), so sessions survive
  client disconnects *and* daemon restarts; the next `tyd up` re-adopts them and
  re-grants the creator's caps
- Sequenced output log on the live-agent (byte-offset seq, disk segments, 64MB
  cap): `read` resumes from a cursor without taking the attach slot; attach/watch
  still replay the 64KB ring
- `tyd session read` pulls output by cursor, with `--json` for one record per
  page and `--follow` to stream until the shell exits
- `tyd session send` injects keystrokes without taking the attach slot, and
  `read --wait` holds a page open until bytes arrive
- `read` wake conditions — `idle_ms`, `match` (RE2 over the cleaned terminal
  text), `max_bytes` — so a caller can say "wake me when the prompt appears"
  instead of polling. `send` returns the cursor it wrote at, so a stateless
  caller can read only the output its own keystrokes caused

`send` writes **raw terminal bytes**, the same encoding `write` uses. It is not
a non-interactive `exec`: it types into the session's shell, so the shell
interprets it, line discipline applies, and the output still comes back through
`read`. It does not start a shell — a session whose shell has exited says so
instead. `read` is the only way to see what `send` caused, which is what makes
the pair scriptable.

### Step 2 — Identity and session authorization

- `tyd keygen`, `trusted.json`, auto-created identity
- Ed25519 challenge-response on every connection
- Capabilities: `list`, `create`, `attach`, `write`, `resize`, `signal`, `close`
- `attach` ≠ `write`; session grants bind to `session_id`
- Creator receives in-memory owner caps for the new session

### Step 3 — Transport and topology

- Transport abstraction: `unix` | `tls` | `quic` | `relay`
- TLS listen available (default **off**; enable with `--listen 127.0.0.1:61211`)
- Certificate pin via `--tls-cert`; TLS 1.3 minimum
- `tyd status` connection topology
- CI release artifacts for linux / darwin / freebsd (amd64 + arm64)

## Control-plane pairing

Full requirements: [requirements/control-plane-pairing.md](requirements/control-plane-pairing.md).

### Step 1 — Requirements + minimal CP pairing skeleton

- Requirements doc + this phased roadmap
- In-repo Control Panel service (local/tests): register → allocate id; invite (10m TTL); accept → exchange peer public keys
- CP stores pairing metadata only (ids + public keys); **no** session/TTY data
- `tyd up` primary daemon start; auto-identity; default TCP listen **off**; unix socket kept
- `tyd register` / `tyd accept` with `--platform` (default `https://app.getfda.dev`)
- Paired peer keys persisted locally (`peers.json`)

### Step 2 — Data-plane self-network after pairing

- Peer AuthN with exchanged keys (inbound peers injected into server trust on sync)
- Ephemeral CP signaling: `PUT/GET /v1/daemons/{id}/endpoint` (addr + cert fingerprint + transport + candidates; TTL ~90s; no TTY)
- Data frames never through CP — the client dials the peer directly
- `tyd up --data-listen auto` starts the data plane when registered; publishes/refreshes the endpoint
- **Phase 1:** QUIC listen on all interfaces + multi-candidate dial (see [dataplane-networking.md](requirements/dataplane-networking.md)); default data plane is QUIC (`transport=quic`)
- **Phase 3 MVP:** WebSocket relay on CP `/relay` (default `https://app.getfda.dev/relay`) plus optional compose `relay`; direct first, relay as fallback
- Session targeting: `--peer <id|nickname>` for dialing commands; recent peer / single-outbound defaults; `~/.tyd/recent.json`
- Client catalog `~/.tyd/sessions.json`: `session list` is local-only; create stores the dial address for later attach

### Step 3 — Approval modes

- Enforce `pre` / `post` / `full` from `peers.json` `Registration.ApprovalMode` on `tyd up`
- **pre**: every remote (TLS or QUIC) request waits for a local `tyd session approve`; unix bypasses; an approval is one-shot, expires after 10m, and is bound to one request — approving a create does not release a later send, and several waiting requests need `--digest` to choose between them
- **post**: auto-create like full; control events audited
- **full** (default): unchanged create; no per-session review
- `approve` / `reject` protocol + CLI (unix transport only)
- `tyd approval <full|pre|post>` switches mode in place (keeps daemon id and peers)
- `tyd up --audit-log PATH` writes JSON Lines in any mode; `--session-idle-timeout D` reaps unattended sessions (default off)

### Step 4 — Session alias, defaults, status UX

- Session alias (`tyd session alias`; the old top-level `tyd alias` is deprecated); stored in `~/.tyd/aliases.json`
- `attach` / `watch` / `close` / `approve` / `reject` accept an alias or omit the id → recent session
- Recent-session peer placeholder defaults (Step 2 `--peer` / `recent.json`) + help placeholder
- `status` shows CP registration, peers, recent, session aliases, and daemon connections
- Create-then-attach (optional `--detach`); SSH-style `--verbose` connect debug; client-local session catalog for `list`

### Step 5 — Revoke and hardening

- `tyd revoke <peer-id|nickname>` — either side drops the pair on CP and locally
- `tyd invite` mints a new 10-minute invite; `tyd invite revoke <token>` invalidates unused invites
- CP prunes used/expired invites; JSON bodies capped; peer sync **replaces** (so revokes propagate)
- Inbound trust drops revoked peer keys (`DropUnlistedPeers`); a data-plane create then fails AuthN

### Step 6 — Surviving a failing disk

- Atomic writes for every state file: a failed write keeps the previous version
- Daemon keeps registration/peers in memory; `peers.json` is a cache, write failures are retried
- An unparsable `peers.json` is quarantined and recovered from the CP without relaxing the approval mode
- `tyd doctor [--fix]` for state/disk self-check and rebuild

### Step 7 — Surviving a restarted Control Panel

The Control Panel keeps its registrations in memory, so restarting it — a
deploy, a crash, a reboot — used to leave every daemon publishing into a 404
until somebody restarted `tyd up` on each host, and the whole fleet sat on the
relay until they did. A 404 out of a maintenance round is now answered with the
restore the daemon already does at startup, and the round is retried so the
endpoint goes back out in the same pass.

- 404 on the round → `POST /v1/restore` from local `peers.json`, retried
  in the same round. Restore is keyed by this daemon's own id and public key and
  cannot mint an identity, so the automatic path has the same authority as the
  startup one; trust still comes from `paired.json`
- Recovery is idempotent and bounded: one line per event on stderr, never a loop
- Poll backoff 30s → 1m → 2m → 5m, reset on success, so a Control Panel that is
  down is not dialled on a fixed timer (a 500 is not a 404: no restore attempt)
- ±20% jitter, so a fleet started together does not arrive as one spike
- The Control Panel client keeps an explicit idle pool instead of leaning on
  `http.DefaultTransport`, so a poller reuses its TLS session between rounds
- `PUT /v1/daemons/{id}/sync` publishes the endpoint and returns the peer list in
  one request, halving what a fleet asks of a Control Panel. It calls the same
  `PublishEndpoint` and `ListPeers` the two routes do, so the proof checks and
  the TTL cap cannot drift between them
- A daemon newer than its Control Panel finds no `/sync`, falls back to the two
  requests, and says so once — the alternative was a daemon republishing into a
  404 forever, which is what a self-hosted Control Panel on an older commit
  would otherwise have caused

A Control Panel that is *unreachable* is still a single point of failure for
pairing: nothing can mint an invite until it is back. Surviving that is a
different step — see [dataplane-networking.md](requirements/dataplane-networking.md)
for why the relay cannot be clustered today.

## Peer management

- `tyd peer list` — paired peers with nickname and direction
- `tyd peer show <id|alias>` — peer detail, published endpoint, reachability
- `tyd peer alias <id|nick> <name>` / `peer alias rm` — nickname a peer for `--peer` targeting
- `tyd <session>.<peer>` — attach shortcut (`tyd jammy.laptop` is `tyd --peer laptop session attach jammy`)

## Not done (intentionally)

| Item | Notes |
|------|--------|
| Tailcat / NetBird / STUN / custom relay | Superseded by [dataplane-networking.md](requirements/dataplane-networking.md): Phase 1 QUIC direct, Phase 2 WG, Phase 3 relay |
| WireGuard data plane | Phase 2 after QUIC direct |
| Bind TLS on `0.0.0.0` by default | Default stays off / loopback when TLS is enabled |
| SSH protocol or sshd dependency | Out of scope |
| Switch shell to another Unix user (setuid) | Not implemented |
| Full TTY recording in CP | **Forbidden** — CP pairing metadata only |
| Server-side session database | The session catalog is client-local and advisory; the daemon holds live sessions in memory plus live-agents |
| Multiple writers on one session | A second attaching writer is rejected |
| File transfer, port forward, non-interactive exec | Belong above tyd |
