# tyd

[![CI](https://github.com/fdaio/tyd/actions/workflows/ci.yml/badge.svg)](https://github.com/fdaio/tyd/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fdaio/tyd)](https://github.com/fdaio/tyd/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

**tyd maintains persistent, remotely attachable terminal sessions on a machine.**

A daemon holds PTY/shell sessions on a target host. A client pairs with that host,
then creates or attaches sessions; the shell keeps running when the client goes
away. tyd is not an agent, not a VPN, and not a file-transfer tool.

Not related to [ttyd](https://github.com/tsl0922/ttyd) (share your terminal over
the web). `app.getfda.dev` is fdaio's hosted Control Panel; point `--platform` at
your own instance to keep pairing metadata inside your network.
[docs/connect.md](docs/connect.md)

## Why tyd

- Sessions outlive the client **and** the daemon. Each session runs in a process of
  its own under `~/.tyd/live/`, so a shell keeps running across a `tyd up` restart
  and the next daemon adopts it again. Reconnect to the same shell from another
  device.
- Pairs by token, not by account. Control Panel and relay are both self-hostable,
  and `--relay` takes a list so you are not tied to one rendezvous.
- One binary for both ends. No SSH/VPN stack to configure; it layers on whatever
  network you already trust (LAN, WireGuard, Tailscale).

How it compares to `tmux + ssh`, mosh, and Tailscale SSH — including where tyd
adds nothing: [docs/alternatives.md](docs/alternatives.md)

## Security model

- **Identity**: Ed25519 keys in `~/.tyd`; each connection runs a
  challenge-response against the peer's `trusted.json`. A new key needs an
  explicit pairing.
- **Transport**: TLS 1.3 minimum with a pinned server certificate fingerprint
  (direct), or TLS 1.3 negotiated *through* the relay between the two peers
  (dual-NAT fallback) — the relay relays ciphertext and never sees session bytes.
  See [relay path security](docs/protocol.md#relay-path-security) for what a
  relay can still observe.
- **Control Plane**: stores daemon ids, public keys, and dial metadata. Session
  and TTY bytes never reach it.
- **Local boundary**: a session runs as the same user as the daemon, so approval
  modes and audit logs gate a *remote* peer, not code already running in a
  session. What that means, and what to do about it, is in
  [security.md](docs/security.md).
- **Local by default**: the daemon listens only on `~/.tyd/tyd.sock` until you
  register; the QUIC data plane binds `0.0.0.0:0` (random port, every interface)
  when registered. `tyd up --data-listen 127.0.0.1:0` keeps that listener on
  loopback, `off` removes it — see
  [data plane and relay](docs/operations.md#data-plane-and-relay).
- **Invites** are single-use tokens that expire 10 minutes after the Control Panel
  mints them. Approval modes are `full`, `pre`, or `post`. An audit log is
  independent of the mode: `tyd up --audit-log FILE` records control events (never
  terminal content) under any of them, and without that flag only `post` records
  anything, on stderr.

## Install

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

Per-user install, no sudo. What it does:

- downloads the latest GitHub Release for your platform — one `tyd-<os>-<arch>.tar.gz`
  holding a single binary, about 3.7MB — installs `tyd` into `~/.local/bin/tyd`,
  and keeps state in `~/.tyd`;
- starts a per-user daemon that keeps running after your shell exits —
  `systemd --user` (with `loginctl enable-linger`) on Linux, a LaunchAgent on
  macOS, `nohup` elsewhere. Nothing restarts the `nohup` fallback, so it does not
  come back after a reboot; on a host with neither systemd nor launchd, start
  `tyd up` again yourself or install a service of your own;
- in a TTY, asks whether to mint a pairing invite. It does **not** touch your
  shell profile, and never uses `sudo`.

Prefer to read it first? Fetch the script out of this repository:

```bash
curl -fsSL https://raw.githubusercontent.com/fdaio/tyd/main/scripts/install.sh -o install.sh && less install.sh
```

`app.getfda.dev/install.sh` serves that same file. The archives it downloads are
not signed, but GitHub publishes a SHA-256 digest for each one on the
[release page](https://github.com/fdaio/tyd/releases/latest) if you want to check
what you got.

> Saved `install.sh` from before 2026-09-28? Fetch it again: release archives are
> now named per architecture, so an old copy asks for a name that no longer
> exists.

Non-interactive installs:

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

Supported platforms: Linux, macOS, FreeBSD on amd64 and arm64. Windows is not
supported.

> **Agent?** See [docs/agent.md](docs/agent.md) — one-line install, `--agent` / `--client --accept` recipes, tool model, and troubleshooting for LLM agents.

## Use

On the machine that holds the shells:

```bash
tyd approval pre                      # set the mode before tyd up reads it
tyd up                                # daemon
tyd invite                            # mint a pairing token, wait 10 minutes
tyd invite --no-wait                  # mint it and exit immediately
```

Both forms wait for the peer to accept, counting the token's remaining life down
on screen; it expires 10 minutes after it was minted either way. Press `Ctrl-C`
to revoke. `invite` prints the peer command to run:

```
Invite minted.

  url                   https://app.getfda.dev/tyd/6cbf1a02e8d94715
  approval              pre
  invite ttl            10m0s
  relay                 https://app.getfda.dev/relay (offers on tyd up)

Copy and run on the peer:
  tyd accept 8f1d4c60b29a4e37
```

`url` is this daemon's page on the Control Panel, not a credential. The token on
the `tyd accept` line is the one the peer needs, and it is derived here rather
than issued by the Control Panel, so the Control Panel cannot use it to stand in
for this host.

`pre` is the mode worth starting with for a peer you have not used before: every
remote create, attach, and watch waits for a `tyd session approve` on this
machine, and each approval covers one request. `full` is the default and starts
a shell as soon as the peer asks. `tyd approval pre` switches without changing
the daemon id or any pairing, and a `tyd up` restart applies it; a host with no
registration yet wants `tyd register --approval pre` instead. See
[approval modes](docs/session.md#approval-modes).

On the peer machine, after installing tyd:

```bash
tyd accept TOKEN --as laptop          # pair
tyd --peer laptop session create      # create a shell and attach
tyd session alias jammy               # name the most recent session
tyd jammy.laptop                      # = tyd --peer laptop session attach jammy
tyd session list                      # local catalog
tyd session watch jammy               # read-only follow
tyd session close jammy               # end the session
```

`session watch` and `session close` take a **session** id or alias, not a peer
nickname. With more than one paired peer, pass `--peer` to the commands that dial
a daemon; `session list` never dials and ignores `--peer`.

```
$ tyd session list
SESSION           ALIAS  PEER     STATE     CREATED
8c97d14ce9389e0c  jammy  laptop  DETACHED  2026-09-28T02:37:14Z

$ tyd peer list    # newest pairing first
ID                ALIAS   DIRECTION  PAIRED
15cd9c1a653274e7  laptop  outbound   2026-09-28T02:36:59Z
```

`Ctrl-\` detaches and leaves the shell running; `session close` ends the session. A
shell that exits on its own (`exit`, Ctrl-D) leaves the session `EXITED` and still
attachable. Pairing, dual-NAT, and network details: [docs/connect.md](docs/connect.md).

## Uninstall

There is no `tyd uninstall`. Close your sessions first — each one is a shell
process that outlives the daemon:

```bash
tyd session list
tyd session close <id>                # repeat for every row
```

Then stop the daemon and its autostart entry:

```bash
# Linux (systemd user unit)
systemctl --user disable --now tyd.service && rm ~/.config/systemd/user/tyd.service
loginctl disable-linger "$(id -un)"   # the installer turns this on
# macOS (LaunchAgent)
launchctl unload ~/Library/LaunchAgents/dev.getfda.tyd.plist
# nohup fallback
kill "$(cat ~/.tyd/tyd.pid)"
```

Finally, remove the files. Deleting `~/.tyd` deletes the Ed25519 identity, so every
peer must pair again:

```bash
rm -f ~/.local/bin/tyd                 # or your PREFIX
rm -rf ~/.tyd
```

Pairing survives on the Control Panel: unpair it there, or run
`tyd revoke laptop --force` on the peer first.

## Documentation

Start with [docs/overview.md](docs/overview.md) for the architecture and
non-goals, then [docs/connect.md](docs/connect.md) to pair.

| Doc | Contents |
|-----|----------|
| [docs/agent.md](docs/agent.md) | Agent handbook — one-line install, `--agent` / `--client` recipes, tool model, `tyd mcp` for a model, troubleshooting |
| [docs/overview.md](docs/overview.md) | What tyd is, architecture, non-goals |
| [docs/connect.md](docs/connect.md) | Install, pair, connect, detach, close |
| [docs/session.md](docs/session.md) | Session lifecycle, aliases, approval modes, audit log |
| [docs/alternatives.md](docs/alternatives.md) | How tyd relates to tmux + ssh, mosh, and Tailscale SSH |
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
`~/.local`) and starts the per-user daemon (systemd --user, a LaunchAgent, or
a detached process). That daemon keeps running after the shell exits. A
`DESTDIR` install only stages the binary and does not start anything. The
[install script](#install) downloads the latest GitHub Release and does the same daemon setup.

## Contributing

Run `make test` (it compiles, so it is also the build check) and open a pull
request against `main`. Scope one change per PR; describe the observable
behaviour you changed and how you verified it.

## License

Apache-2.0 — see [LICENSE](LICENSE).
