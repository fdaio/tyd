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

### Step 1 — REQ + minimal CP pairing skeleton (this)

- Requirements doc + this phased roadmap
- In-repo Control Panel service (local/tests): register → allocate id; invite (10m TTL); accept → exchange peer public keys
- CP stores pairing metadata only (ids + public keys); **no** session/TTY data
- `tyd up` primary daemon start (`serve` alias OK); auto-identity; default TCP listen **off**; unix socket kept
- `tyd register` / `tyd accept` with `--platform` (default `https://app.getfda.dev`)
- Persist paired peer keys locally (`peers.json`)

### Step 2 — Data-plane self-network after pairing

- Peer AuthN with exchanged keys
- Direct / signaling path **without** CP storing TTY
- CP may offer **ephemeral signaling** (endpoint exchange) only
- Session commands targeting peers (`--peer` / nickname)

### Step 3 — Approval modes

- Enforce pre-approval / post-approval / full (default) as declared at register

### Step 4 — Session alias + defaults + status UX

- Session alias (`tyd alias` for sessions, not peers)
- Recent-session peer placeholder defaults (0/1/many peer rules)
- Status shows CP connection + peers

### Step 5 — Revoke + hardening

- Peer revoke; invite edge cases; production hardening

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
