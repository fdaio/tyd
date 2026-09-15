# Roadmap: done and not done

## Done

### Step 1 — Persistent local PTY

- Single binary `tyd`
- `serve` / `create` / `list` / `attach` / `close`
- PTY + shell; resize; SIGINT-style signals via PTY control bytes
- Client disconnect / detach leaves shell running; reattach works
- In-process sessions only (lost on daemon restart)

### Step 2 — Identity and session authorization

- `tyd keygen`, `trusted.json`
- Ed25519 challenge-response on every connection
- Capabilities: `list`, `create`, `attach`, `write`, `resize`, `signal`, `close`
- `attach` ≠ `write`; grants bind to `session_id`
- Creator receives in-memory owner caps for the new session

### Step 3 — Transport + topology

- Transport abstraction: `unix` | `tls`
- Default TLS listen `127.0.0.1:61211`
- Certificate pin via `--tls-cert`
- `tyd status` connection topology
- CI release artifacts for linux / darwin / freebsd (amd64 + arm64)

## Not done (intentionally)

| Item | Notes |
|------|--------|
| Tailcat / NetBird / STUN / custom relay | Connectivity overlay; future Transport backend candidate |
| Bind TLS on `0.0.0.0` by default | Default stays loopback |
| SSH protocol or sshd dependency | Out of scope |
| Control plane / short-lived tickets | Still static trust file |
| Switch shell to another Unix user (setuid) | Not implemented |
| Audit log of operations / TTY recording | Reserved for later |
| Persist / restore sessions across daemon restart | |
| Multiple writers on one session | Second attach with write is rejected |
| Idle / session timeout policy | |
| File transfer, non-interactive exec, FDA approval UX | Belong above tyd |

## Suggested next steps (not committed)

1. Optional Transport backend using Tailcat (or similar) for NAT/relay — still the same frame protocol
2. Audit events (who / when / which session / which op), without full TTY capture at first
3. Control-plane issued short credentials replacing static long-lived trust entries
