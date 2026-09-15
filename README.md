# tyd

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

It holds PTY/shell sessions on a target host. Clients may attach, detach, and reattach without killing the shell. It is not an agent, not a VPN, and not a file-transfer tool.

Completed so far: local detachable PTY, Ed25519 identity + session capabilities, Transport (`unix` + TLS), Control Panel pairing (Steps 1–2), and approval modes (Step 3: `full` / `pre` / `post`).

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
./tyd session list
./tyd status
./tyd session attach "$id"           # Ctrl-\ detaches; shell keeps running
./tyd session watch "$id"            # read-only; Ctrl-C / Ctrl-\ stops watch
./tyd session close "$id"            # marks CLOSED; kept in list until daemon restart
```

Identity is created automatically on first `up` / `register` / `accept` (optional `tyd keygen`).

TLS (opt-in):

```bash
./tyd up --listen 127.0.0.1:61211
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt session create
```

## Control Panel pairing (Step 1)

Local CP for tests / self-host:

```bash
go run ./cmd/controlpanel -listen 127.0.0.1:8080
./tyd --platform http://127.0.0.1:8080 register   # prints invite token
./tyd --platform http://127.0.0.1:8080 accept <token> --as peer-nick
```

Default production platform URL: `https://app.getfda.dev`. CP stores pairing metadata (ids + public keys) only — never session/TTY data. See the requirements doc and roadmap Steps 4–5 for session alias and revoke.

## CLI layout

| Group | Commands |
|-------|----------|
| Root | `up`, `serve` (alias), `status`, `keygen`, `register`, `accept` |
| `session` | `create`, `list`, `attach`, `watch`, `approve`, `reject`, `close` |

## Defaults

| Item | Path / value |
|------|----------------|
| Unix socket | `~/.tyd/tyd.sock` |
| TLS listen | **off** (enable with `--listen 127.0.0.1:61211`) |
| Identity | `~/.tyd/id_ed25519` |
| Trust file | `~/.tyd/trusted.json` |
| Peers file | `~/.tyd/peers.json` |
| Platform | `https://app.getfda.dev` |
| Server cert/key | `~/.tyd/server.crt`, `~/.tyd/server.key` |

`attach` ≠ `write`. A key granted only `attach` can watch output (via `attach` or `watch`) but cannot type. `watch` is read-only and does not take the exclusive attach lock.
