# tyd

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

It holds PTY/shell sessions on a target host. Clients may attach, detach, and reattach without killing the shell. It is not an agent, not a VPN, and not a file-transfer tool.

Completed so far: local detachable PTY, Ed25519 identity + session capabilities, and a Transport layer (`unix` + TLS) with connection topology.

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/overview.md](docs/overview.md) | Positioning, architecture, boundaries |
| [docs/guide.md](docs/guide.md) | Install, keygen, serve, session, TLS, status |
| [docs/protocol.md](docs/protocol.md) | Frame protocol, auth handshake, capabilities |
| [docs/roadmap.md](docs/roadmap.md) | Done (steps 1–3) and not done |

## Quick start

```bash
make build
./tyd keygen
./tyd serve                          # unix socket + TLS on 127.0.0.1:61211

id=$(./tyd session create)
./tyd session list
./tyd status
./tyd session attach "$id"           # Ctrl-\ detaches; shell keeps running
./tyd session watch "$id"            # read-only; Ctrl-C / Ctrl-\ stops watch
./tyd session close "$id"            # marks CLOSED; kept in list until daemon restart
```

TLS client (pin the server certificate):

```bash
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt session create
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt status
```

## CLI layout

| Group | Commands |
|-------|----------|
| Root | `keygen`, `serve`, `status` |
| `session` | `create`, `list`, `attach`, `watch`, `close` |

## Defaults

| Item | Path / value |
|------|----------------|
| Unix socket | `~/.tyd/tyd.sock` |
| TLS listen | `127.0.0.1:61211` |
| Identity | `~/.tyd/id_ed25519` |
| Trust file | `~/.tyd/trusted.json` |
| Server cert/key | `~/.tyd/server.crt`, `~/.tyd/server.key` |

`attach` ≠ `write`. A key granted only `attach` can watch output (via `attach` or `watch`) but cannot type. `watch` is read-only and does not take the exclusive attach lock.
