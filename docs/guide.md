# User guide

## Install

Release binary (linux / darwin / freebsd):

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

Installs for the current user (`~/.local/bin`, no sudo). Pairing and session steps for humans and automation: [connect.md](connect.md).

## Build from source

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
./tyd register --force                    # replace registration; invalidates peers
```

Already registered: `tyd register` requires `--force` or a TTY `y/N` confirm. Force replaces the
CP daemon (new id), clears local peers, and warns that existing pairings are invalid until peers
accept a new invite. Non-TTY without `--force` errors.

`tyd up` reuses `~/.tyd/peers.json` (same daemon id). If CP lost that daemon, `up` restores via
`POST /v1/restore` (id + pubkey + peers) before publishing the data-plane endpoint — it does not
mint a new registration.

### Docker Compose

```bash
cp .env.example .env   # optional; default base URL is https://app.getfda.dev
make dist && cp dist/tyd-*.tar.gz releases/
docker compose up -d --build
curl -s http://127.0.0.1:${TYD_CP_PORT:-8080}/healthz
curl -fsSL http://127.0.0.1:${TYD_CP_PORT:-8080}/releases/tyd-linux.tar.gz -o /dev/null
./tyd register                                  # platform defaults to https://app.getfda.dev
```

`curl …/install.sh | sh` downloads binaries from the same Control Panel origin
(`…/releases/tyd-<os>.tar.gz`), so the GitHub repo may stay private.

`--platform` is only needed for a custom / local Control Panel (e.g. `--platform http://127.0.0.1:8080`).

Container listens on `0.0.0.0:8080` (no TLS inside — terminate at Cloudflare).  
Compose caps the running CP at about half a CPU and 128MB; the image build uses Alpine
and a single-threaded compile so a 1C/1G host can build on-box (add ~1G swap if OOM).  
Default in-repo CP state is **in-memory**; restart loses pairing metadata until daemons `up` and
restore from local `peers.json`. See `Dockerfile.controlpanel` and `docker-compose.yml`.

Paired peer public keys are stored in `~/.tyd/peers.json`.  
CP stores pairing metadata only. Revoke removes the pair on CP; the next daemon peer-sync drops inbound trust.

### Data plane (Step 2 / Phase 1 direct candidates)

After register, `tyd up --data-listen auto` (default) starts a **QUIC** data-plane listener
on all interfaces (`0.0.0.0:0`), publishes `addr` + `candidates` + cert fingerprint to CP
with `transport=quic` (ephemeral signaling only). Refresh every ~30s. Client dials try
candidates in order; if all fail, tyd falls back to `--relay` (default
`https://relay.getfda.dev`) like Tailcat — direct first, relay last.

```bash
./tyd up --platform http://127.0.0.1:8080   # auto data-plane when registered
./tyd up --data-listen off                  # disable data-plane
./tyd up --advertise example.com            # put this host first in candidates
./tyd up --relay http://127.0.0.1:9090      # dual-NAT fallback rendezvous
./tyd up --relay off                        # disable relay offer/fallback
```

Relay deploy (separate from CP; TLS at the edge):

```bash
docker compose up -d relay
# public: relay.getfda.dev → container :9090
```

See [dataplane-networking.md](requirements/dataplane-networking.md) for WG (Phase 2) and relay details.

Peer **create / attach / watch / close** (direct QUIC; data plane not through CP):

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
id=$(./tyd session create --detach)  # starts local daemon on demand if unix socket is down
./tyd session list                   # local catalog; alive first, newest first; no PID/SIZE
./tyd alias jammy                    # name the recent session (or: tyd alias "$id" jammy)
./tyd session attach jammy           # silent by default; Ctrl-\ detaches
./tyd session attach jammy --verbose # SSH-style debug1: lines on stderr
./tyd session watch                  # omit → recent session
./tyd session attach "$id"           # reattach; shell still running
./tyd session close jammy            # kill shell; catalog marks CLOSED
./tyd session watch jammy            # dump history from ring, then end
```

Default `session create` **attaches** after create (use `--detach` to print the id only).
Local unix targets auto-start `tyd up` when the socket is not listening; peer/`--addr` targets never start a local daemon.
Connect progress is off by default. With `--verbose`, create/attach/watch print SSH-style `debug1:` lines on stderr (resolve → dial → attach).
Each dial candidate is capped (~12s for connect + TLS + auth); Ctrl-C cancels create/attach/watch before the session is live.
If attach uses a cached `sessions.json` address that fails, tyd refreshes the peer endpoint from CP and retries once.

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

Stored in `peers.json` and enforced by `tyd up`. Set at register time with
`tyd register --approval full|pre|post`, or change it later without
re-registering:

```bash
./tyd approval          # print the current mode
./tyd approval pre      # switch; keeps the daemon id and all pairings
```

`tyd approval` updates the Control Panel and `peers.json`; restart `tyd up` to
apply. If the CP is unreachable the mode is still saved locally, because the
daemon is what enforces it.

| Mode | Behavior |
|------|----------|
| `full` (default) | Remote create starts a shell immediately |
| `post` | Same create as full; control events are audited (see below) |
| `pre` | Every remote create, attach, and watch waits for a local decision |

Under `pre`, "remote" means any non-unix transport — TLS and QUIC alike. Local
unix-socket work bypasses the gate, because that is the operator.

```bash
# On the machine running the daemon (unix socket):
./tyd session list                   # PENDING sessions appear in the alive group
./tyd session approve "$id"          # starts PTY → DETACHED
./tyd session reject "$id"           # removes pending session
```

A remote attach or watch under `pre` is refused with `attach pending approval`
and recorded as a waiting request; the same `tyd session approve <id>` releases
it. **Approvals are one-shot**: approving a create also covers the attach that
follows it, but every later reattach is reviewed again, so access never becomes
permanent. Requests and approvals expire after 10 minutes.

Approve / reject are accepted only over the local unix socket, never over TLS.

### Audit log

Auditing is independent of the approval mode — any mode can write it:

```bash
./tyd up --audit-log ~/.tyd/audit.log
```

One JSON object per line, file created `0600`, appended across restarts:

```json
{"time":"2026-09-18T03:11:52Z","event":"attach_pending","session_id":"a1b2","principal":"laptop","transport":"quic","approval_mode":"pre"}
```

Events: `create`, `create_pending`, `approve`, `reject`, `attach`,
`attach_pending`, `detach`, `close`, `idle_close`, `denied`. Records carry
metadata only — terminal input and output never enter the log. Without
`--audit-log`, `post` mode still writes the same records to stderr, and `full` /
`pre` write nothing.

### Idle sessions

Sessions live until closed. To expire unattended ones:

```bash
./tyd up --session-idle-timeout 8h   # default: off
```

A session counts as idle from the moment the last client detaches; attaching
resets the clock. `PENDING` sessions are never reaped — they wait for you.

Detach / watch-exit keys:

| Action | Effect |
|--------|--------|
| `Ctrl-\` (attach) | Detach; PTY/shell keep running |
| `Ctrl-C` / `Ctrl-\` (watch) | Stop watching; session unchanged |
| Client crash / socket drop | Same: session stays |
| `tyd session close <id>` | Kill shell; mark `CLOSED` in the local catalog |

## When the disk fills up

State files under `~/.tyd` are a cache of what the daemon already holds in
memory and what the Control Panel already knows. A failing disk degrades tyd;
it does not stop it.

- **Writes never destroy the previous file.** Every state file is written to a
  temporary file and renamed into place, so a write that fails on a full disk
  leaves the last good version intact.
- **Memory is authoritative.** The daemon reads `peers.json` once at startup.
  The maintenance loop works from memory, retries the write each tick, and says
  so once when the file becomes writable again. Paired peers keep their access
  while the disk is full.
- **A damaged `peers.json` is set aside, not trusted.** On startup the file is
  renamed to `peers.json.corrupt.<timestamp>` and the registration and peer list
  are pulled back from the CP using this daemon's identity. The daemon id and
  the pairings survive, and the approval mode is taken from the CP rather than
  reset — recovery never relaxes a `pre` or `post` daemon to `full`.
- **Audit write failures warn once** and sessions carry on.

If the CP is also unreachable, the daemon keeps serving local sessions and
tells you to run `tyd doctor --fix` once the disk is healthy.

### `tyd doctor`

```bash
./tyd doctor         # check state files, free space, and writability
./tyd doctor --fix   # set a damaged peers.json aside and rebuild it from the CP
```

`doctor` loads each file the way tyd does, so it reports the real failure
rather than just "file exists". It exits non-zero when something is broken:

```
ok   disk             38.3 GiB free on /home/user/.tyd
ok   writable         /home/user/.tyd
fail peers            /home/user/.tyd/peers.json: empty (truncated by a failed write?)
```

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
| `approval` | Show or set approval mode without re-registering |
| `doctor` | Check state files and disk; `--fix` rebuilds `peers.json` from the CP |
| `invite revoke` | Invalidate an unused invite |
| `accept` | Accept an invite; store peer public key |
| `revoke` | Revoke a paired peer |
| `alias` | Name a session (client-local) |

### `session` commands

| Command | Role |
|---------|------|
| `session create` | Create and attach; `--detach` prints `session_id` only (PENDING never attaches) |
| `session list` | List local catalog (alive first, newest first; no PID/SIZE) |
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
