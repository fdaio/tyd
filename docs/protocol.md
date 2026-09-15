# Protocol and authorization

The application protocol is independent of Transport. Any reliable bidirectional byte stream can carry it (today: Unix socket or TLS).

## Framing

Each message is:

```text
uint32 big-endian length N
N bytes JSON
```

Maximum frame size: 1 MiB.

## Message types

### Client → server

| Type | Purpose | Typical capability |
|------|---------|--------------------|
| `auth` | Response to challenge (pubkey + signature) | — (handshake) |
| `create` | Create session | `create` |
| `list` | List sessions | `list` |
| `status` | List connection topology | `list` |
| `attach` | Attach to session (exclusive writer/viewer) | `attach` on that session |
| `watch` | Read-only observe (or dump closed history) | `attach` on that session |
| `write` | Bytes to PTY | `write` |
| `resize` | Rows/cols | `resize` |
| `signal` | e.g. `INT`, `TSTP` | `signal` |
| `detach` | Leave attach/watch without killing shell | (must be attached/watching) |
| `close` | Close session (kept until daemon restart) | `close` |

### Server → client

| Type | Purpose |
|------|---------|
| `challenge` | Random nonce for Ed25519 sign |
| `ok` | Success (auth or create) |
| `error` | Failure string |
| `sessions` | List result |
| `connections` | Status / topology result |
| `attached` | Attach succeeded |
| `watching` | Watch succeeded |
| `output` | PTY output bytes |
| `detached` | Detach acknowledged |
| `exit` | Shell exited (or closed-session watch finished) |
| `closed` | Session close acknowledged |

## Authentication handshake

On every new connection, before any other command:

```text
server → challenge { data: nonce }
client → auth      { public_key, data: signature(nonce) }
server → ok | error
```

Server accepts only public keys present in the trust store. Bad signature → `authentication failed`. Unknown key → `untrusted public key`.

## Authorization rules

| Capability | Scope | Notes |
|------------|-------|-------|
| `list` | global | Also required for `status` |
| `create` | global | On success, creator gets owner caps on the new session (in memory) |
| `attach` | per session | Read/follow output (`attach` or `watch`); **not** write |
| `write` | per session | Keyboard / stdin to PTY |
| `resize` | per session | |
| `signal` | per session | |
| `close` | per session | |

Owner caps after create: `attach`, `write`, `resize`, `signal`, `close`.

## Connection topology payload

`status` → `connections` entries include roughly:

```json
{
  "id": "…",
  "transport": "unix" | "tls",
  "local_addr": "…",
  "remote_addr": "…",
  "tls": true,
  "cert_fp": "first 16 hex of SHA-256",
  "state": "handshaking" | "authenticated" | "attached",
  "principal": "local",
  "session_id": "…",
  "established_at": "RFC3339"
}
```

This is the daemon’s view of **control connections**, not a mesh/network path graph.

## Transport

| Kind | Dial | Listen |
|------|------|--------|
| `unix` | `--socket` (default `~/.tyd/tyd.sock`) | always (unless misconfigured) |
| `tls` | `--addr host:port` + `--tls-cert` pin | `--listen` (default `127.0.0.1:61211`, or `off`) |

TLS details:

- TLS 1.3
- Self-signed server cert generated on demand
- Client verifies by **certificate fingerprint pin**, not the system CA pool
