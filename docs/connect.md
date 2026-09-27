# Connect to a tyd server

tyd holds a persistent shell on a **server**. A **client** pairs with that server,
then creates or attaches sessions. Session bytes never go through the Control Panel.

## Install

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

Binaries are downloaded from the same origin as the script (`/releases/`), so the
GitHub repository can stay private.

- **Human, TTY:** choose server or client. After a server install you can mint an
  invite and copy one client command.
- **Automated / no TTY:** treated as a server. Prints one client bootstrap line.

```bash
# Server, non-interactive: install, register, print the client command
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent

# Client: install and accept an invite
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

**Do not use sudo.** tyd holds your own shells, so everything installs for the
invoking user: the binary goes to `~/.local/bin` (override with `TYD_BINDIR`) and
the daemon runs under **systemd --user** (Linux), a **LaunchAgent** (macOS), or
**nohup** if neither is available. There is no system-wide service.

Environment overrides: `TYD_PLATFORM` (Control Panel URL), `TYD_BINDIR`,
`TYD_RELEASE_URL`, `TYD_INSTALL_URL`. A custom Control Panel otherwise needs
`--platform URL` or `TYD_PLATFORM`.

## Pair

The server must be registered and running:

```bash
tyd up                 # daemon
tyd invite --no-wait   # mint a token (10 minute TTL)
```

Hand the peer the token, as a one-liner:

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
```

or, if tyd is already installed there:

```bash
tyd accept TOKEN --as laptop
```

`register` and `invite` wait for the peer by default (with a TTL countdown;
Ctrl-C revokes the invite); `--no-wait` prints the accept line and exits.

Either side can drop the pair later:

```bash
tyd revoke laptop
```

## Connect

On the **client**, after pairing:

```bash
tyd peer list                            # paired peers and nicknames
tyd --peer laptop session create         # create a shell and attach
```

With an existing session:

```bash
tyd session list
tyd session attach <id-or-alias>         # Ctrl-\ detaches; the shell keeps running
tyd session watch <id-or-alias>          # read-only
```

Omit the session id to reuse the most recent one (`recent.json`; also shown in
`tyd status`).

The **server** must stay up — `tyd status` should not report the local daemon as
down. Published data-plane addresses expire on the Control Panel about every 90
seconds, so a long-lived pairing keeps refreshing them only while `tyd up` runs.

## Detach and close

| Action | Command / key |
|--------|----------------|
| Leave the shell running | `Ctrl-\` while attached |
| Follow output only | `tyd session watch` |
| End the shell, keep the session | `exit` or Ctrl-D inside the shell → `EXITED` |
| End the session | `tyd session close <id-or-alias>` |

Detach is not close, and neither is a shell that exits on its own. `exit`,
Ctrl-D, a crash, or a kill ends only the shell: the session turns `EXITED` and
stays attachable, so the next `tyd session attach` replays what that shell printed
and starts a new one for the same session id. `session close` is the deliberate
end of a session — it marks the session `CLOSED` in the client catalog, where the
row remains as history.

## Dual NAT / no public IP

Pairing metadata stays on the Control Panel; TTY bytes are never stored there.
After pairing, the client tries the server's published **QUIC** candidates first.
If every direct dial fails — typical when both sides are behind NAT with no public
address — tyd falls back to a **blind WebSocket relay** (default
`https://app.getfda.dev/relay` on the CP origin). Direct first, rendezvous last.

- No extra flag is needed once the Control Panel serves `/relay`.
- Optional dedicated relay: compose service `relay` or `go run ./cmd/relay`, then
  point the server at it with `--relay URL`.
- The server offers its daemon id on the relay automatically during `tyd up`;
  `--relay off` disables both offering and fallback.

Details: [operations.md](operations.md),
[requirements/dataplane-networking.md](requirements/dataplane-networking.md).

## See also

- [session.md](session.md) — session lifecycle, aliases, approval modes
- [operations.md](operations.md) — daemon flags, data plane, Docker, recovery
- [overview.md](overview.md) — what tyd is and is not
