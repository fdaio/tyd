# Roadmap: done and not done

## Done (local sessions)

### Local Step 1 — Persistent local PTY

- Single binary `tyd`
- `serve` / `session create|list|attach|close` / `status` / `keygen`
- PTY + shell; resize; SIGINT-style signals via PTY control bytes
- Client disconnect / detach leaves shell running; reattach works
- In-process sessions only (lost on daemon restart)

### Local Step 2 — Identity and session authorization

- `tyd keygen`, `trusted.json`
- Ed25519 challenge-response on every connection
- Capabilities: `list`, `create`, `attach`, `write`, `resize`, `signal`, `close`
- `attach` ≠ `write`; grants bind to `session_id`
- Creator receives in-memory owner caps for the new session

### Local Step 3 — Transport + topology

- Transport abstraction: `unix` | `tls`
- TLS listen available (default now **off**; enable with `--listen 127.0.0.1:61211`)
- Certificate pin via `--tls-cert`
- `tyd status` connection topology
- CI release artifacts for linux / darwin / freebsd (amd64 + arm64)

## Control-plane pairing (phased)

Full requirements: [docs/requirements/control-plane-pairing.md](requirements/control-plane-pairing.md).

### Step 1 — REQ + minimal CP pairing skeleton

- Requirements doc + this phased roadmap
- In-repo Control Panel service (local/tests): register → allocate id; invite (10m TTL); accept → exchange peer public keys
- CP stores pairing metadata only (ids + public keys); **no** session/TTY data
- `tyd up` primary daemon start (`serve` alias OK); auto-identity; default TCP listen **off**; unix socket kept
- `tyd register` / `tyd accept` with `--platform` (default `https://app.getfda.dev`)
- Persist paired peer keys locally (`peers.json`)

### Step 2 — Data-plane self-network after pairing (done)

- Peer AuthN with exchanged keys (inbound peers injected into server trust on sync)
- Ephemeral CP signaling: `PUT/GET /v1/daemons/{id}/endpoint` (addr + cert fingerprint; TTL ~90s; no TTY)
- Data frames never through CP — client dials peer TLS directly (`DialTLSFingerprint`)
- `tyd up --data-listen auto` starts loopback data-plane TLS when registered; publishes/refreshes endpoint
- Session targeting: `--peer <id|nickname>`; recent peer / single-outbound defaults; `~/.tyd/recent.json`

### Step 3 — Approval modes (done)

- Enforce pre / post / full from `peers.json` `Registration.ApprovalMode` on `tyd up`
- **pre**: TLS creates stay `PENDING` until local `tyd session approve`; unix creates bypass
- **post**: auto-create; audit line on close (stderr / `AuditLog`)
- **full** (default): unchanged create; no per-session review
- `approve` / `reject` protocol + CLI (unix transport only)

### Step 4 — Session alias + defaults + status UX (done)

- Session alias (`tyd alias` for sessions, not peers); stored in `~/.tyd/aliases.json`
- `attach` / `watch` / `close` / `approve` / `reject` accept alias or omit id → recent session
- Recent-session peer placeholder defaults (Step 2 `--peer` / `recent.json`) + help placeholder
- `status` shows CP registration, peers, recent, session aliases, and daemon connections

### Step 5 — Revoke + hardening (done)

- `tyd revoke <peer-id|nickname>` — either side drops the pair on CP and locally
- `tyd invite` mints a new 10-minute invite; `tyd invite revoke <token>` invalidates unused invites
- CP prunes used/expired invites; JSON bodies capped; peer sync **replaces** (so revokes propagate)
- Inbound trust drops revoked peer keys (`DropUnlistedPeers`); data-plane create then fails AuthN

## Not done (intentionally)

| Item | Notes |
|------|--------|
| Tailcat / NetBird / STUN / custom relay | Connectivity overlay; candidate behind Step 2 signaling |
| Bind TLS on `0.0.0.0` by default | Default stays loopback when TLS enabled |
| SSH protocol or sshd dependency | Out of scope |
| Switch shell to another Unix user (setuid) | Not implemented |
| Full TTY recording in CP | **Forbidden** — CP pairing metadata only |
| Persist / restore sessions across daemon restart | |
| Multiple writers on one session | Second attach with write is rejected |
| Idle / session timeout policy | |
| File transfer, non-interactive exec, FDA approval UX | Belong above tyd |
