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
| `read` | One non-blocking page of sequenced output (`cursor`) | `attach` on that session |
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
| `read_result` | Reply to `read`: `data`, `cursor_next`, `dropped`, `at_end`, `epoch`, `cursor_ahead` |

## Authentication handshake

On every new connection, before any other command:

```text
server → challenge { version, data: nonce }       nonce is 32 bytes
client → auth      { version, public_key, data: sig }
server → ok | error
```

`version` is the handshake protocol version, and it is **outside the signature**,
on purpose. A version that was signed could only be checked after verification,
and verification is what fails identically for an old peer and for an impostor —
so the whole reason for the field would be lost. Each side refuses a version it
cannot speak before it verifies anything or signs anything.

The accepted range is `1..version`, where `version` is the current value. A peer
that sends no version field is older than every version there is. The only
permitted answer to a version outside the range is **refusal**: negotiating a
version, or accepting one the peer chose, would hand an attacker the choice of
protocol. Both numbers and the side to upgrade are in the error, because
`handshake failed` cannot tell an old peer from an impostor.

A build from before this field existed sends no version, so it is refused by any
build that has it. That break is deliberate and loud: the old side still sees only
an authentication failure, so the improvement available to it lands on the new
side, which logs the refusal and reports the peer's version rather than leaving an
unexplained bad signature.

The next incompatible change raises the current version, and the one after that
folds the version into the channel binding, where it is authenticated instead of
merely carried.

`sig` is `Ed25519(auth payload)` where the auth payload is

```text
"tyd-auth-v1\0" || len(nonce) as uint16be || nonce || binding
```

`binding` is the [channel binding](#relay-path-security) of the connection: the
TLS exporter on every transport that carries TLS (`tls`, `quic`, and the inner
TLS on `relay`), and empty on `unix`, which has no TLS session. The client
refuses a challenge that is not exactly 32 bytes rather than signing it.

The label keeps this signature apart from the binding signature the same key
makes in the `bound` frame, so the two can never be replayed as each other.
The binding keeps it apart from every *other* connection: a peer that takes a
challenge from another daemon, gets it signed here, and answers that daemon
with the result is refused, because the signature covers the session it was
made on. That is why the client must refuse to sign bytes it did not expect:
without the length check and the binding, a compromised paired peer could log
in to any other daemon as this client.

Server accepts only public keys present in the trust store. Bad signature → `authentication failed`. Unknown key → `untrusted public key`. A client that signs the bare nonce, as tyd did before the labelled payload, is reported as an older tyd and refused rather than accepted.

## Authorization rules

| Capability | Scope | Notes |
|------------|-------|-------|
| `list` | global | Also required for `status` |
| `create` | global | On success, creator gets owner caps on the new session (in memory) |
| `attach` | per session | Read/follow output (`attach`, `watch`, or `read`); **not** write. `read` can return up to the on-disk log (default 64MB), not only the 64KB attach ring. |
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

## Keystroke injection

`send` types into a session without taking the exclusive attach slot. It is
live-agent only, like `read`.

Request:

```json
{"type":"send","session_id":"…","data":"echo hi\n"}
```

`data` uses the same encoding as `write`: raw PTY bytes, base64 in JSON, at
most 64KB per call. It needs the **write** capability, not `attach`. The shell
interprets the bytes, so this is typing, not a non-interactive `exec`: line
discipline applies and the result comes back through `read`.

Reply is `ok` carrying the byte count written, plus the `cursor` (the output
end **before** the write) and its `epoch`. A caller that sends and then reads
from that cursor sees only what its own keystrokes produced; without it the
read would race the echo and could pick up a prompt from earlier.

```json
{"type":"ok","cursor_next":8,"cursor":165,"epoch":1}
```

A send that fails part way still reports the bytes that did land, in
`cursor_next` on the `error` reply. Nothing is written after the reply, so a
retry resumes from that count. The errors are deliberate and explicit:

| Error | Meaning |
|-------|---------|
| `session in use: attached elsewhere` | Someone holds the exclusive attach slot. Deliberately does not name them. |
| `send timed out` | The PTY did not accept the input in time. `cursor_next` is what landed. |
| `preempted` | An `attach` took the session. `cursor_next` is what landed. |
| `session busy: a send is in progress` | A second send arrived. It is refused, never queued. |
| `send is larger than the 64KB queue` | The data exceeds one call, which is also the AF_UNIX-era cap on input. |
| `shell exited; attach to start a new one` | The shell is gone. `send` never starts one. |
| `session pending approval` | A remote create that has not been approved. |
| `send is not supported on in-process sessions` | No live-agent behind this session. |

The timeout is a server-side default of 5s, set with
`--session-send-timeout` and capped at 30s. An `attach`, `watch`, `read`,
`close`, `resize` or `signal` never waits for a send: `attach` preempts it.

Under `pre`, `send` is gated exactly like `read`: the same one-shot approval,
spent at the start of the request, and not re-checked while a read waits.
That makes `read --follow` impractical under `pre`, because every page needs
its own approval.

## Sequenced output read

`read` is a one-shot RPC. It does not take the exclusive attach slot, so a
human can `watch` or `attach` at the same time. It is live-agent only:
an in-process PTY (tests, no `tyd up`) replies `error` with
`read is not supported on in-process sessions`.

Request:

```json
{"type":"read","session_id":"…","cursor":0,"epoch":1,"wait_ms":0}
```

`wait_ms` is optional and defaults to 0, which returns at once. With a
non-zero value the server holds the reply until bytes arrive, the wait
elapses, or the reply has to say something anyway. The server clamps the wait
to 30s and allows at most 16 parked reads per session. A `cursor_ahead` or a
`dropped` prefix is returned immediately without waiting.

### Wake conditions

Three optional fields decide *why* a waiting read returns. They sit alongside
`wait_ms`, which stays the overall deadline.

| Field | Range | Returns when |
|-------|-------|--------------|
| `idle_ms` | 50–30000 | Output has been quiet this long, measured from the last byte after the cursor. The clock only starts once at least one byte has arrived, so a session that says nothing waits for the timeout instead. |
| `match` | RE2, ≤512 bytes | The cleaned text matches. |
| `max_bytes` | ≤65536 | This many bytes have accumulated after the cursor. The reply is cut to exactly that, backed off to a rune boundary, so `cursor_next` is exact. |

Any condition needs `wait_ms > 0`; without it the server returns an error
rather than returning at once, which is the opposite of what was asked. With
no condition the read behaves exactly as before, so an older client is
unaffected.

With a condition, data already sitting at the cursor is **not** enough. The
read keeps waiting until a condition is met, the wait runs out, or the shell
ends. `cursor_ahead` and a dropped prefix still return at once.

`match` is evaluated against the terminal text a person would see: ANSI and
OSC escapes removed, CRLF folded to a newline, a lone CR treated as redrawing
the line, and a backspace erasing the character before it. An incomplete
escape at the end of what has arrived is held back rather than guessed at, so
a prompt split across two writes does not match on its first half. Only the
last 16KB is examined, and the pattern is run at most every 20ms so a session
that floods output cannot spend the CPU on it. RE2 is linear time, so the
pattern itself cannot be a denial of service.

The reply carries `reason`:

| `reason` | Meaning |
|----------|---------|
| `available` | No condition was given and there was data, or a prefix was dropped |
| `match` / `idle` / `max_bytes` | That condition fired |
| `timeout` | The wait ran out with no condition met |
| `exited` | The shell is gone and the reply is at the end of the stream |
| `cursor_ahead` | The cursor had to be reset |

`reason` and the `exited` flag always agree: `reason` is *why* the read
returned, `exited` is that the stream is finished.

`cursor` is a byte offset from the first output byte of that session (seq 0).
Omit `epoch` (or send 0) on the first pull; after that, send the `epoch` from
the last `read_result`.

`read` flushes pending bytes to the kernel before it replies, so a `kill -9` of
the live-agent cannot leave a client cursor past what is on disk. Epoch still
bumps on an unclean restart (missing `output.clean`) so a power loss, or a
disk-full hole, cannot reuse offsets the client already saw.

A later agent continues seq from the durable files. An `epoch` mismatch still
serves a cursor that sits inside the previous epoch's durable end; only a
cursor past that bound returns `cursor_ahead`. Adopt `cursor_next` and `epoch`
from a `cursor_ahead` reply; do not keep the old cursor.

Bytes produced while no agent was alive cannot be recovered. That gap is
permanent.

Reply (`read_result`):

| Field | Meaning |
|-------|---------|
| `data` | Raw PTY bytes, same JSON encoding as `attached` / `output` `data`. At most 64KB. Page with `cursor_next`. |
| `cursor_next` | Offset after `data`. Use it as the next `cursor`. On `cursor_ahead`, this is the seq to resume from. |
| `dropped` | If `cursor` is in a prefix the disk already deleted: `earliest - cursor`. The reply starts at the earliest readable byte. Not an error. |
| `at_end` | No further bytes are known yet. If `data` is empty and `cursor_ahead` is false, `cursor_next` equals the request `cursor` (or the earliest seq when `dropped` forced a skip on an empty remainder). The call does not wait. |
| `epoch` | Generation of this log. Send it on the next `read`. |
| `cursor_ahead` | The request cursor is past durable seq, or past the previous epoch's durable end. `data` is empty. Adopt `cursor_next` and `epoch`. An `epoch` mismatch with a cursor still inside that durable end is served and the reply carries the current `epoch`. |
| `exited` | The shell is gone and the reply is at the end of the stream. Nothing more will arrive, so a follower should stop. A parked read returns this at once rather than waiting out its timeout. |

Hot attach/watch still replay only the 64KB in-memory ring. The disk log is
for `read`. Default cap is 64MB per session (`--session-output-log-max`), in
4MB segments. Files are `0600` under `~/.tyd/live/<id>/` and are deleted with
the session. They are **not** the `--audit-log` chain: that log still never
records terminal bytes. A full disk stops new segment writes and keeps the
PTY on the 64KB ring (`seq` still advances). Live `read` can return those ring
bytes; they are not durable, and after restart a cursor in that range is
`cursor_ahead`. `tyd doctor` reports `output.err`.

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

**The binding is not only for the relay.** The login signature carries the
binding of the connection it was made on, on every transport that has TLS, so
one peer's login cannot be carried to another. Before that, a paired peer that
was compromised could take a challenge from a second daemon, have the client
sign it, and log in to the second daemon as this client. The `unix` socket has
no TLS session and no binding; see [The local
boundary](security.md#the-local-boundary) for why that is not a boundary
either.

**Metadata the Control Panel holds** is listed in
[alternatives.md](alternatives.md#what-a-third-party-can-see).
