# Connect to a tyd server

tyd holds a persistent shell on a **server**. A **client** pairs with that server, then creates or attaches sessions. Session bytes never go through the Control Panel.

## Install

One-click (Control Panel at app.getfda.dev; binaries from the same origin `/releases/`):

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

- **Human, TTY:** choose server or client. After a server install, you can mint an invite and copy a client command.
- **Automated / no TTY:** treated as server. Prints one client bootstrap line on stdout.

```bash
# Server (non-interactive): install daemon, register, print client command
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent

# Client: install binary and accept the invite
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

**Do not use sudo.** tyd holds your own shells, so everything installs for the invoking user: the binary goes to `~/.local/bin` (override with `TYD_BINDIR`) and the daemon runs under **systemd --user** (Linux), a **LaunchAgent** (macOS), or **nohup** if neither is available. There is no system-wide service. Clients do not run a resident `tyd up`; local session commands start the daemon on demand when needed.

Custom Control Panel: `--platform URL` or `TYD_PLATFORM`.

## Request access (pairing)

The server must be registered and running (`tyd up`). Then mint an invite (about 10 minutes TTL):

```bash
tyd invite --no-wait
```

Give the peer this one-liner (token from the invite output):

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

Or, if tyd is already installed on the client:

```bash
tyd accept TOKEN --as laptop
```

Either side can drop the pair later: `tyd revoke <peer-id|nickname>`.

## Connect

On the **client**, after pairing:

```bash
tyd peer list
tyd --peer <id-or-nick> session create    # creates a shell and attaches
```

If you already have a session:

```bash
tyd session list
tyd session attach <id-or-alias>          # Ctrl-\ detaches; the shell keeps running
tyd session watch <id-or-alias>           # read-only
```

Omit the session id to reuse the most recent one (`tyd status` / `recent.json`).

The **server** must stay up (`tyd status` should not say the local daemon is down). Data-plane addresses expire on the Control Panel after about 90s without `tyd up`.

### Dual NAT / no public IP

Peer traffic never goes through the Control Panel. After pairing, the client tries the
server’s published **QUIC** candidates first. If every direct dial fails (typical when
both sides are behind NAT with no public address), tyd falls back to **`tyd-relay`**
(default `https://app.getfda.dev/relay`) — same idea as Tailcat: direct first, rendezvous last.

- Deploy relay separately (compose service `relay`, or `go run ./cmd/relay`); put TLS at the edge.
- Server `tyd up` offers its daemon id on the relay automatically.
- Client needs no extra flags if the default relay URL is reachable; use `--relay URL` or `--relay off`.

Details: [guide.md](guide.md), [dataplane-networking.md](requirements/dataplane-networking.md).

## Detach and close

| Action | Command / key |
|--------|----------------|
| Leave the shell running | `Ctrl-\` while attached |
| Follow output only | `tyd session watch` |
| Kill the shell | `tyd session close <id-or-alias>` |

`session close` marks the session closed in the client catalog. Detach is not close.

## See also

- [guide.md](guide.md) — flags, approval modes, TLS, relay
- [overview.md](overview.md) — what tyd is and is not
- [dataplane-networking.md](requirements/dataplane-networking.md) — QUIC + relay
