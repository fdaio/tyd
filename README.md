# tyd

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

It holds PTY/shell sessions on a target host. Clients may attach, detach, and reattach without killing the shell. It is not an agent, not a VPN, and not a file-transfer tool.

Completed so far: local detachable PTY, Ed25519 identity + session capabilities, Transport (`unix` + TLS + QUIC data-plane), Control Panel pairing including data-plane, approval modes, session aliases, peer/invite revoke, client-local session catalog (`session list` without CP/daemon), create-then-attach UX, and optional SSH-style `--verbose` connect debug.

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/overview.md](docs/overview.md) | Positioning, architecture, boundaries |
| [docs/connect.md](docs/connect.md) | Pair, connect, detach, close (human and automated) |
| [docs/guide.md](docs/guide.md) | Install, up, session, TLS, pairing pointers |
| [docs/protocol.md](docs/protocol.md) | Frame protocol, auth handshake, capabilities |
| [docs/roadmap.md](docs/roadmap.md) | Done + control-plane pairing steps |
| [docs/requirements/control-plane-pairing.md](docs/requirements/control-plane-pairing.md) | CP pairing requirements (full) |

## Install

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

No sudo: the binary lands in `~/.local/bin` and the daemon runs as the invoking user (systemd `--user`, a macOS LaunchAgent, or `nohup`).

TTY: choose **server** or **client**. After a server install you can invite a client and copy one command. Non-interactive / `--agent` installs a server and prints the client bootstrap on stdout. Details: [docs/connect.md](docs/connect.md).

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

## Quick start (from source)

```bash
make build
id=$(./tyd session create --detach)   # starts local daemon on demand; scripts: print id only
# interactive (default): ./tyd session create  → create then attach
./tyd alias work                     # name the recent session
./tyd session list                   # local catalog (~/.tyd/sessions.json); no CP/daemon
./tyd status
./tyd session attach work            # or omit id to reuse recent; Ctrl-\ detaches
./tyd session watch                  # recent session; Ctrl-C / Ctrl-\ stops
./tyd session close work             # marks CLOSED in the local catalog
```

Identity is created automatically on first `up` / `register` / `accept` / on-demand local session (optional `tyd keygen`).

A **client** machine does not need `tyd up` to list sessions or to talk to a peer.
Local `session create` / `attach` / `watch` / `close` start the daemon on demand if
the unix socket is down — you do not have to keep a resident `tyd up` by hand.

TLS (opt-in):

```bash
./tyd up --listen 127.0.0.1:61211
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt session create --detach
```

## Control Panel pairing

Local CP for tests:

```bash
go run ./cmd/controlpanel -listen 127.0.0.1:8080
./tyd --platform http://127.0.0.1:8080 register   # prints accept line; waits until peer accepts (Ctrl-C revokes)
./tyd --platform http://127.0.0.1:8080 accept <token> --as peer-nick
# production: tyd register  →  peer pastes stdout; use --no-wait to print and exit
./tyd --peer peer-nick session create   # CP signaling once, then direct dial; attaches by default
./tyd session list                      # still local — does not hit CP
./tyd revoke peer-nick
```

### Docker Compose (production-oriented)

Control Panel only (no TLS in the container — put Cloudflare or another edge in front):

```bash
cp .env.example .env   # optional; edit TYD_CP_BASE_URL / TYD_CP_PORT
docker compose up -d --build
curl -s http://127.0.0.1:8080/healthz   # ok
curl -fsSL http://127.0.0.1:8080/install.sh | head -1
./tyd register                          # --platform defaults to https://app.getfda.dev
```

Local / self-hosted CP only: `./tyd --platform http://127.0.0.1:8080 register`.

Files: `Dockerfile.controlpanel`, `docker-compose.yml`, `.env.example`.  
Runtime is capped (~0.5 CPU / 128MB) for small VPS; build uses Alpine + single-threaded
`go build` to lower peak RAM. On 1C/1G, add ~1G swap if the first build is OOM-killed.  
**In-memory only** — restarting the container drops registrations, invites, and peer pairs.

CP stores pairing metadata (ids + public keys) only — never session/TTY data.

## CLI layout

| Group | Commands |
|-------|----------|
| Root | `up`, `serve` (alias), `status`, `keygen`, `register`, `invite`, `accept`, `revoke`, `alias` |
| `session` | `create`, `list`, `attach`, `watch`, `approve`, `reject`, `close` |

## Defaults

| Item | Path / value |
|------|----------------|
| Unix socket | `~/.tyd/tyd.sock` |
| TLS listen | **off** (enable with `--listen 127.0.0.1:61211`) |
| Identity | `~/.tyd/id_ed25519` |
| Trust file | `~/.tyd/trusted.json` |
| Peers file | `~/.tyd/peers.json` |
| Recent | `~/.tyd/recent.json` |
| Session aliases | `~/.tyd/aliases.json` |
| Session catalog | `~/.tyd/sessions.json` (client-local; used by `session list`) |
| Platform | `https://app.getfda.dev` |
| Server cert/key | `~/.tyd/server.crt`, `~/.tyd/server.key` |

`attach` ≠ `write`. A key granted only `attach` can watch output (via `attach` or `watch`) but cannot type. `watch` is read-only and does not take the exclusive attach lock.
