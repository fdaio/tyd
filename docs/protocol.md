# Protocol and authorization

The application protocol is independent of Transport. Any reliable bidirectional byte stream can carry it (today: Unix socket, TLS, QUIC, or a relay splice).

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
| `close` | Close session (kept as history until daemon restart) | `close` |
| `approve` | Start PTY for a `PENDING` session | `create` (unix transport only) |
| `reject` | Remove a `PENDING` session | `create` (unix transport only) |

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
| `exited` | Shell exited; the session stays attachable and is now `EXITED` |
| `exit` | Session closed, or a closed-session watch finished |
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
  "transport": "unix" | "tls" | "quic" | "relay",
  "local_addr": "…",
  "remote_addr": "…",
  "tls": true,
  "cert_fp": "SHA-256 hex of the server certificate (status shows the first 16)",
  "state": "handshaking" | "authenticated" | "attached",
  "principal": "local",
  "session_id": "…",
  "established_at": "RFC3339"
}
```

This is the daemon’s view of **control connections**, not a mesh/network path graph.

Frames never change shape because of where the PTY lives: the daemon proxies them
to a per-session live-agent process, so a session keeps working across a daemon
restart with the same protocol.

## Transport

| Kind | Dial | Listen / path |
|------|------|----------------|
| `unix` | `--socket` (default `~/.tyd/tyd.sock`) | always (unless misconfigured) |
| `tls` | `--addr host:port` + `--tls-cert` pin | `--listen` (default off) |
| `quic` | peer endpoint from CP (`transport=quic` + cert fingerprint) | `--data-listen auto` on registered `tyd up` |
| `relay` | `--relay URL` (WebSocket; default CP `/relay`) after direct fails | server offers on the same `--relay` during `tyd up` |

TLS details:

- TLS 1.3
- Self-signed server cert generated on demand
- Client verifies by **certificate fingerprint pin**, not the system CA pool

QUIC data-plane and relay fallback: [dataplane-networking.md](requirements/dataplane-networking.md).
The relay is a **blind WebSocket splice** (default `https://app.getfda.dev/relay` on the CP).
The hub does not interpret what it carries, but "blind" is not "private": see
[Relay path security](#relay-path-security) below for what a relay can and
cannot observe.

While a splice is up, the relay pings each WebSocket leg every 15s. Those are
WebSocket control frames, not bytes in the terminal stream, so a quiet session
is not cut by Cloudflare's idle timeout (about 100s).

## Relay path security

The relay is a rendezvous and a byte courier. It is not trusted with the
session's contents, and it is not able to change them undetected.

**What the relay sees**

- Both peers' IP addresses and ports, and when each connected
- The daemon id and peer id used to match the two sides, and the ticket that
  pairs them
- Byte counts and timing in each direction
- WebSocket framing, and the TLS handshake bytes of the inner session

**What the relay cannot see or do**

- Session content: TTY bytes, commands, file contents, resize and signal
  events. The two peers negotiate TLS 1.3 *inside* the splice, so the relay
  copies ciphertext.
- Alter the stream undetectably. TLS 1.3 rejects a modified record.
- Inject bytes as if the peer had typed them. Injected bytes either fail their
  record or drop the connection; they are never delivered as session input.
- Impersonate either peer. After the handshake each side proves its Ed25519
  identity over the TLS exporter (the *channel binding*). A relay that
  terminates TLS on its own and forwards the plaintext derives a different
  exporter, so the peer's signature does not verify and the client refuses to
  continue.
- Downgrade silently. A peer that does not start TLS is refused with an
  explicit error; there is no plaintext mode.

**Why the binding is not a certificate pin.** The Control Panel's peer record
carries a public key but no daemon id, so a client dialling through a relay
cannot look up the peer's certificate fingerprint; and a relay-only daemon
never publishes one. The peer's Ed25519 public key comes from pairing, is
already the anchor for every other peer, and works here unchanged. A binding
signature over the exporter also catches a relay that re-originates TLS, which
a bare certificate pin would not.

**Metadata the Control Panel holds** is listed in
[alternatives.md](alternatives.md#what-a-third-party-can-see).
