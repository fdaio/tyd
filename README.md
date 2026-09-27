# tyd

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

A daemon holds PTY/shell sessions on a target host. A client pairs with that host,
then creates or attaches sessions; the shell keeps running when the client goes
away. tyd is not an agent, not a VPN, and not a file-transfer tool.

## Install

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

Per-user install, no sudo: the binary lands in `~/.local/bin` and the daemon runs
under `systemd --user` (Linux), a LaunchAgent (macOS), or `nohup`.

Non-interactive installs:

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

## Use

On the machine that holds the shells:

```bash
tyd up                                # daemon
tyd invite --no-wait                  # mint a pairing token for a peer
```

On the peer machine, after installing tyd:

```bash
tyd accept TOKEN --as laptop          # pair
tyd --peer laptop session create      # create a shell and attach
tyd session list                      # local session catalog
tyd session watch laptop              # read-only follow
tyd session close laptop              # kill the shell
```

`Ctrl-\` detaches and leaves the shell running; `session close` ends it. Pairing,
dual-NAT, and network details: [docs/connect.md](docs/connect.md).

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/overview.md](docs/overview.md) | What tyd is, architecture, non-goals |
| [docs/connect.md](docs/connect.md) | Install, pair, connect, detach, close |
| [docs/session.md](docs/session.md) | Session lifecycle, aliases, approval modes, audit log |
| [docs/operations.md](docs/operations.md) | Running the daemon, data plane, relay, Docker, recovery |
| [docs/cli.md](docs/cli.md) | Command and flag reference |
| [docs/protocol.md](docs/protocol.md) | Frame protocol, auth handshake, capabilities |
| [docs/roadmap.md](docs/roadmap.md) | What exists today, what is deliberately absent |
| [docs/requirements/control-plane-pairing.md](docs/requirements/control-plane-pairing.md) · [dataplane-networking.md](docs/requirements/dataplane-networking.md) | Pairing and data-plane requirements |

## Build from source

```bash
git clone git@github.com:fdaio/tyd.git && cd tyd
make test
make build       # ./tyd
make install     # ~/.local/bin/tyd
```

`make test` compiles the packages on its own, so it runs before `make build`.
`make install` copies the binary to `$(PREFIX)/bin` (`PREFIX` defaults to
`~/.local`). It does not change `PATH` or install a service. The
[install script](#install) does both.
