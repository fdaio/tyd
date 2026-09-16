# User guide

## Build

```bash
git clone git@github.com:fdaio/tyd.git
cd tyd
make build    # produces ./tyd
make test
```

## First-time setup

Identity is created automatically on first `tyd up`, `tyd register`, or `tyd accept`.
Optional explicit keygen:

```bash
./tyd keygen
```

Writes:

- `~/.tyd/id_ed25519` — private identity (mode 0600)
- `~/.tyd/id_ed25519.pub` — public key
- `~/.tyd/trusted.json` — bootstrap trust (this key gets `list` + `create`) if the file did not exist
- Later, as a **client**: `~/.tyd/sessions.json` — local session catalog (written on create; read by `session list`)
- `~/.tyd/aliases.json` / `~/.tyd/recent.json` — client-local names and last peer/session

Prints the public key (base64) on stdout.

## Start the daemon

```bash
./tyd up
```

(`tyd serve` remains as a deprecated alias.)

By default listens on:

- Unix: `~/.tyd/tyd.sock`
- TLS: **off** (enable with `--listen`)

Useful flags:

```bash
./tyd up                                          # unix only (default)
./tyd up --listen 127.0.0.1:61211                 # enable TLS
./tyd up --socket /tmp/tyd.sock --trust /path/trusted.json
./tyd up --tls-cert /path/server.crt --tls-key /path/server.key
```

## Control Panel pairing

See [requirements/control-plane-pairing.md](requirements/control-plane-pairing.md) and [roadmap.md](roadmap.md).

```bash
go run ./cmd/controlpanel -listen 127.0.0.1:8080
./tyd --platform http://127.0.0.1:8080 register
# stays open with TTL countdown until peer accepts (Ctrl-C revokes invite)
./tyd --platform http://127.0.0.1:8080 accept <invite> --as laptop
./tyd --peer laptop session create
./tyd invite                              # another invite; waits like register
./tyd invite --no-wait                    # print accept line and exit
./tyd invite revoke <token>               # unused invite
./tyd revoke laptop                       # drop pairing (either side)
```

### Docker Compose

```bash
export TYD_CP_BASE_URL=https://app.getfda.dev   # public origin behind Cloudflare
docker compose up -d --build
curl -s http://127.0.0.1:${TYD_CP_PORT:-8080}/healthz
./tyd register                                  # platform defaults to https://app.getfda.dev
```

`--platform` is only needed for a custom / local Control Panel (e.g. `--platform http://127.0.0.1:8080`).

Container listens on `0.0.0.0:8080` (no TLS inside — terminate at Cloudflare).  
State is **in-memory**; restart loses pairing metadata. See `Dockerfile.controlpanel` and `docker-compose.yml`.

Paired peer public keys are stored in `~/.tyd/peers.json`.  
CP stores pairing metadata only. Revoke removes the pair on CP; the next daemon peer-sync drops inbound trust.

### Data plane (Step 2 / Phase 1 direct candidates)

After register, `tyd up --data-listen auto` (default) starts a **TLS** data-plane listener
on all interfaces (`0.0.0.0:0`), publishes `addr` + `candidates` + cert fingerprint to CP
(ephemeral signaling only). Refresh every ~30s. Client dials try candidates in order;
if all fail, the error lists each attempt (no relay fallback yet). QUIC transport helpers
are in-tree for the next flip to default-QUIC.

```bash
./tyd up --platform http://127.0.0.1:8080   # auto data-plane when registered
./tyd up --data-listen off                  # disable data-plane
./tyd up --advertise example.com            # put this host first in candidates
```

See [dataplane-networking.md](requirements/dataplane-networking.md) for WG (Phase 2) and relay (Phase 3).

Peer **create / attach / watch / close** (direct TLS/QUIC; data plane not through CP):

```bash
./tyd --peer laptop session create   # CP GetEndpoint (or catalog addr later) + direct dial; attaches by default
./tyd session list                   # local catalog only — ignores --peer; no CP / daemon
./tyd session attach amy             # prefer dial addr stored in sessions.json; else resolve peer endpoint
```

`--peer` applies to commands that dial a daemon (`create`, `attach`, `watch`, `close`).
If `--peer` is omitted for those: use `~/.tyd/recent.json` when present; else exactly one outbound peer;
else zero outbound → local unix socket; many outbound → error asking for `--peer`.
`--addr` still overrides for manual TLS.

`session list` never dials: it merges `sessions.json` with aliases/recent.

## Session lifecycle

Session operations live under the `session` subcommand (`tyd session help` lists them):

```bash
id=$(./tyd session create --detach)
./tyd session list                   # local catalog; no CP or daemon
./tyd alias jammy                    # name the recent session (or: tyd alias "$id" jammy)
./tyd session attach jammy           # progress bar on connect, then clears; Ctrl-\ detaches
./tyd session watch                  # omit → recent session
./tyd session attach "$id"           # reattach; shell still running
./tyd session close jammy            # kill shell; catalog marks CLOSED
./tyd session watch jammy            # dump history from ring, then end
```

Default `session create` **attaches** after create (use `--detach` to print the id only).
Attach/watch show a one-line stderr progress (`looking up` → `connecting <transport> <addr>` → `attaching`) that clears when live.

### Session aliases

Aliases are **client-local** (not peers, not stored on the daemon):

```bash
./tyd alias <session_id> <name>
./tyd alias <name>              # names the most recent session
./tyd alias list
./tyd alias rm <name>
```

Stored in `~/.tyd/aliases.json`.

### Approval modes

Declared at `tyd register --approval full|pre|post` and stored in `peers.json`.
`tyd up` enforces the mode:

| Mode | Behavior |
|------|----------|
| `full` (default) | Remote create starts a shell immediately (same as before) |
| `post` | Same create as full; when a session closes, daemon logs an audit line to stderr (id, principal, timestamps; no TTY) |
| `pre` | TLS/data-plane creates return `PENDING` without a shell; local operator must approve |

```bash
# On the machine running the daemon (unix socket):
./tyd session list                   # PENDING sessions appear in the alive group
./tyd session approve "$id"          # starts PTY → DETACHED
./tyd session reject "$id"           # removes pending session
```

`approve` / `reject` are accepted only over the local unix socket (not over TLS).
Unix-socket creates always bypass the pre gate (local admin is trusted).

Detach / watch-exit keys:

| Action | Effect |
|--------|--------|
| `Ctrl-\` (attach) | Detach; PTY/shell keep running |
| `Ctrl-C` / `Ctrl-\` (watch) | Stop watching; session unchanged |
| Client crash / socket drop | Same: session stays |
| `tyd session close <id>` | Kill shell; mark `CLOSED` in the local catalog |

## Status

```bash
./tyd status
```

Prints:

1. **Control Panel** — platform URL, registration id/url, approval mode, published data-plane endpoint (if any)
2. **Peers** — paired peer ids, nicknames, direction
3. **Recent** — last peer / session used by this client (`~/.tyd/recent.json`)
4. **Session aliases** — local names from `~/.tyd/aliases.json`
5. **Connections** — live daemon connections (transport, remote, TLS, principal, attached session)

Connections require a reachable daemon and the `list` capability. CP/peers sections come from local files (+ optional CP endpoint lookup) even if the daemon is down.

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
| `keygen` | Create identity (+ bootstrap trust if missing); also auto on first up/register/accept |
| `up` | Daemon (`serve` is a deprecated alias) |
| `status` | CP registration, peers, aliases, connections |
| `register` | Register with CP, print `tyd accept …`, wait for peer (or `--no-wait`) |
| `invite` | Mint invite, print accept line, wait for peer (10m TTL; or `--no-wait`) |
| `invite revoke` | Invalidate an unused invite |
| `accept` | Accept an invite; store peer public key |
| `revoke` | Revoke a paired peer |
| `alias` | Name a session (client-local) |

### `session` commands

| Command | Role |
|---------|------|
| `session create` | Create and attach; `--detach` prints `session_id` only (PENDING never attaches) |
| `session list` | List the local session catalog (no CP / daemon) |
| `session attach <id>` | Attach interactive I/O (exclusive) |
| `session watch <id>` | Read-only follow / history dump (`attach` cap) |
| `session approve <id>` | Approve PENDING session (local unix only) |
| `session reject <id>` | Reject PENDING session (local unix only) |
| `session close <id>` | Close session (kept as `CLOSED` in list) |

Old root forms (`tyd create`, `tyd list`, …) are rejected with a migration hint.

## Testing trust / TLS locally

Untrusted identity:

```bash
./tyd --identity /tmp/tyd-a --trust /tmp/trust-a.json keygen
./tyd --socket /tmp/tyd.sock --trust /tmp/trust-a.json --listen off serve
# other terminal:
./tyd --identity /tmp/tyd-b --trust /tmp/trust-b.json keygen
./tyd --socket /tmp/tyd.sock --identity /tmp/tyd-b session create --detach   # expect untrusted
```

Automated coverage: `go test ./internal/auth ./internal/server ./internal/transport`.
