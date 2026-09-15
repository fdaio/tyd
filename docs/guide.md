# User guide

## Build

```bash
git clone git@github.com:fdaio/tyd.git
cd tyd
make build    # produces ./tyd
make test
```

## First-time setup

```bash
./tyd keygen
```

Writes:

- `~/.tyd/id_ed25519` — private identity (mode 0600)
- `~/.tyd/id_ed25519.pub` — public key
- `~/.tyd/trusted.json` — bootstrap trust (this key gets `list` + `create`) if the file did not exist

Prints the public key (base64) on stdout.

## Start the daemon

```bash
./tyd serve
```

By default listens on:

- Unix: `~/.tyd/tyd.sock`
- TLS: `127.0.0.1:61211` (creates `~/.tyd/server.crt` / `server.key` on first start)

Useful flags:

```bash
./tyd serve --listen off                          # unix only
./tyd serve --listen 127.0.0.1:61211              # explicit TLS (default)
./tyd serve --socket /tmp/tyd.sock --trust /path/trusted.json
./tyd serve --tls-cert /path/server.crt --tls-key /path/server.key
```

## Session lifecycle

Session operations live under the `session` subcommand (`tyd session help` lists them):

```bash
id=$(./tyd session create)
./tyd session list                   # alive first, then CLOSED; older first within each group
./tyd session attach "$id"           # interactive; Ctrl-\ to detach
./tyd session watch "$id"            # read-only follow; Ctrl-C / Ctrl-\ exits watch
./tyd session attach "$id"           # reattach; shell still running
./tyd session close "$id"            # kill shell; session stays listed as CLOSED
./tyd session watch "$id"            # dump history from ring, then end
```

Detach / watch-exit keys:

| Action | Effect |
|--------|--------|
| `Ctrl-\` (attach) | Detach; PTY/shell keep running |
| `Ctrl-C` / `Ctrl-\` (watch) | Stop watching; session unchanged |
| Client crash / socket drop | Same: session stays |
| `tyd session close <id>` | Kill shell; keep session as `CLOSED` until daemon restart |

## Connection topology

```bash
./tyd status
```

Shows current control connections known to the daemon, including:

- transport (`unix` / `tls`)
- remote address
- whether TLS is on
- short cert fingerprint (TLS)
- state (`handshaking` / `authenticated` / `attached`)
- principal name
- attached `session_id` (if any)
- established time

Requires the `list` capability.

## TLS client

Copy (or share) the server’s `server.crt` to the client machine, then:

```bash
./tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt session create
./tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt status
./tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt session attach "$id"
```

If `--addr` is set, the client uses TLS and ignores `--socket` for that command. The client **pins** the certificate fingerprint; a different cert is rejected (`untrusted server certificate`).

## Trust and permissions

### `trusted.json` shape

```json
{
  "principals": [
    {
      "name": "local",
      "public_key": "<base64 ed25519 public key>",
      "allow": ["list", "create"],
      "sessions": {
        "optional-session-id": ["attach"]
      }
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `allow` | Global: only `list`, `create` |
| `sessions` | Optional map of `session_id` → caps |

Session caps: `attach`, `write`, `resize`, `signal`, `close`.

**`attach` does not imply `write`.**

When an identity with `create` creates a session, tyd grants that identity owner caps (`attach`, `write`, `resize`, `signal`, `close`) **in the running daemon’s memory**. Those grants are not written back to `trusted.json` and disappear if the daemon restarts.

### Untrusted key

A key not listed in `trusted.json` fails the handshake with `untrusted public key`.

## CLI reference

```text
tyd [--socket PATH] [--listen ADDR|off] [--addr HOST:PORT]
    [--identity PATH] [--trust PATH] [--tls-cert PATH] [--tls-key PATH]
    <command>
```

### Root commands

| Command | Role |
|---------|------|
| `keygen` | Create identity (+ bootstrap trust if missing) |
| `serve` | Daemon |
| `status` | List connection topology |

### `session` commands

| Command | Role |
|---------|------|
| `session create` | Create session; print `session_id` |
| `session list` | List sessions (alive first, then closed; older first) |
| `session attach <id>` | Attach interactive I/O (exclusive) |
| `session watch <id>` | Read-only follow / history dump (`attach` cap) |
| `session close <id>` | Close session (kept as `CLOSED` in list) |

Old root forms (`tyd create`, `tyd list`, …) are rejected with a migration hint.

## Testing trust / TLS locally

Untrusted identity:

```bash
./tyd --identity /tmp/tyd-a --trust /tmp/trust-a.json keygen
./tyd --socket /tmp/tyd.sock --trust /tmp/trust-a.json --listen off serve
# other terminal:
./tyd --identity /tmp/tyd-b --trust /tmp/trust-b.json keygen
./tyd --socket /tmp/tyd.sock --identity /tmp/tyd-b session create   # expect untrusted
```

Automated coverage: `go test ./internal/auth ./internal/server ./internal/transport`.
