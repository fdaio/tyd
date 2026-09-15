# tyd

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

It holds PTY/shell sessions on a target host. Clients may attach, detach, and reattach without killing the shell. It is not an agent, not a VPN, and not a file-transfer tool.

Completed so far: local detachable PTY, Ed25519 identity + session capabilities, Transport (`unix` + TLS), Control Panel pairing including data-plane, approval modes, session aliases, and peer/invite revoke.

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/overview.md](docs/overview.md) | Positioning, architecture, boundaries |
| [docs/guide.md](docs/guide.md) | Install, up, session, TLS, pairing pointers |
| [docs/protocol.md](docs/protocol.md) | Frame protocol, auth handshake, capabilities |
| [docs/roadmap.md](docs/roadmap.md) | Done + control-plane pairing steps |
| [docs/requirements/control-plane-pairing.md](docs/requirements/control-plane-pairing.md) | CP pairing requirements (full) |

## Quick start

```bash
make build
./tyd up                             # unix socket; TLS listen off by default

id=$(./tyd session create)
./tyd alias work                     # name the recent session
./tyd session list
./tyd status
./tyd session attach work            # or omit id to reuse recent; Ctrl-\ detaches
./tyd session watch                  # recent session; Ctrl-C / Ctrl-\ stops
./tyd session close work             # marks CLOSED; kept in list until daemon restart
```

Identity is created automatically on first `up` / `register` / `accept` (optional `tyd keygen`).

TLS (opt-in):

```bash
./tyd up --listen 127.0.0.1:61211
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt session create
```

## Control Panel pairing

Local CP for tests:

```bash
go run ./cmd/controlpanel -listen 127.0.0.1:8080
./tyd --platform http://127.0.0.1:8080 register   # prints invite token
./tyd --platform http://127.0.0.1:8080 accept <token> --as peer-nick
./tyd --peer peer-nick session create
./tyd revoke peer-nick
```

### Docker Compose (production-oriented)

Control Panel only (no TLS in the container — put Cloudflare or another edge in front):

```bash
# optional: public origin used in register URLs
export TYD_CP_BASE_URL=https://app.getfda.dev
docker compose up -d --build
curl -s http://127.0.0.1:8080/healthz   # ok
./tyd --platform http://127.0.0.1:8080 register   # or https://app.getfda.dev via Cloudflare
```

Files: `Dockerfile.controlpanel`, `docker-compose.yml`.  
**In-memory only** — restarting the container drops registrations, invites, and peer pairs.

Default client platform URL: `https://app.getfda.dev`. CP stores pairing metadata (ids + public keys) only — never session/TTY data.

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
| Platform | `https://app.getfda.dev` |
| Server cert/key | `~/.tyd/server.crt`, `~/.tyd/server.key` |

`attach` ≠ `write`. A key granted only `attach` can watch output (via `attach` or `watch`) but cannot type. `watch` is read-only and does not take the exclusive attach lock.
