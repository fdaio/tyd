# CLI reference

`tyd --help`, `tyd session help`, and `tyd peer help` are authoritative and track
the binary. This page is the map plus the defaults.

## Commands

| Group | Command | Role |
|-------|---------|------|
| Sessions | `session create` | Create a session and attach (`--detach` prints the id only) |
| | `session list` | List local sessions (alive first, newest first; PEER shows the peer's nickname when it has one) |
| | `session attach` | Attach interactively (exclusive); id, alias, or recent |
| | `<session>.<peer>` | Attach shortcut: `tyd jammy.laptop` is `tyd --peer laptop session attach jammy` |
| | `session watch` | Follow output read-only; id, alias, or recent |
| | `session approve` | Approve a PENDING session, or one waiting request on it (local unix only) |
| | `session reject` | Reject a PENDING session (local unix only) |
| | `session close` | Close a session (kept as history) |
| | `session rm` | Forget a **closed** session in the local catalog (`--force`); its aliases go with it |
| | `session restore` | Put an archived session back in `session list` |
| | `session alias` | Name a session: `<name>`, `<session_id> <name>`, `set`, `list`, `rm` |
| Peers | `peer list` | List paired peers (id, alias, direction), newest pairing first; archived peers are hidden unless `--all` |
| | `peer show <id\|alias>` | Show peer detail, endpoint, reachability, and whether the pairing record verifies |
| | `peer alias <id\|nick> <name>` | Set a peer nickname (`peer alias rm <id\|nick>` clears it) |
| | `peer restore` | Put an archived peer back in `peer list` |
| | `revoke` | Revoke a paired peer (either side), with `--force` |
| Pairing | `keygen` | Generate the Ed25519 identity (also created automatically) |
| | `register` | Register with the Control Panel (`--force` replaces) |
| | `invite` | Mint an invite, print the accept line, wait (10m TTL); `invite revoke <token>` |
| | `accept` | Accept an invite (token or a pasted accept line), `--as <nickname>`. Already paired: print that peer instead of failing. If the peer has a live endpoint, print `tyd session create --peer <nick\|id>` |
| Model | `mcp` | Serve sessions to a model over MCP on stdio. Needs a target: `--peer <id\|nick>`, or `--peer local` for this machine |
| Daemon | `up` | Start the daemon (unix socket; TLS off by default) |
| | `status` | Show CP registration, peers, aliases, connections |
| | `approval` | Show or set the approval mode: `full`, `pre`, `post` |
| | `doctor` | Check state files and disk; `--fix` rebuilds `peers.json` |
| | `serve` | Deprecated alias for `up` |

Removed forms: `tyd create`, `tyd list`, and friends are rejected with a hint to
use `tyd session …`. The top-level `tyd alias` still works but prints a
deprecation note — prefer `tyd session alias`.

## Flags

Accepted as `--flag value` or `--flag=value`, before or after the command.

### Connection

| Flag | Meaning | Default |
|------|---------|---------|
| `--socket PATH` | Unix socket (alias `-socket`) | `~/.tyd/tyd.sock` |
| `--listen ADDR\|off` | Manual TLS listen for `up` | `off` |
| `--data-listen MODE` | QUIC data plane: `auto`, `off`, `HOST:PORT` (`auto` = all interfaces when registered, off otherwise) | `auto` |
| `--advertise HOST` | Host to prefer in published candidates | interface IPs |
| `--addr HOST:PORT` | TLS client endpoint (overrides `--socket` for that command) | — |
| `--peer ID\|NICK` | Target a paired peer for session dial commands. `tyd mcp` uses it as the machine it serves, and `local` means this machine's own daemon | recent, else single outbound; `mcp`: single outbound, else an error |
| `--relay URL[,URL…]\|off` | Dual-NAT rendezvous; offer on and fall back to each in turn | `https://app.getfda.dev/relay` |
| `--tls-cert PATH` | Server certificate / client pin | `~/.tyd/server.crt` |
| `--tls-key PATH` | Server key | `~/.tyd/server.key` |

### Paths and identity

| Flag | Meaning | Default |
|------|---------|---------|
| `--identity PATH` | Client identity | `~/.tyd/id_ed25519` |
| `--trust PATH` | Trust file | `~/.tyd/trusted.json` |
| `--peers PATH` | Paired peers file | `~/.tyd/peers.json` |
| `--aliases PATH` | Session aliases file | `~/.tyd/aliases.json` |
| `--recent PATH` | Recent peer/session file | `~/.tyd/recent.json` |
| `--archive PATH` | Archive marks and use clocks | `~/.tyd/archive.json` |
| `--platform URL` | Control Panel URL | `https://app.getfda.dev` |

### Behavior

| Flag | Meaning |
|------|---------|
| `--approval MODE` | Approval mode at register time: `full`, `pre`, `post` (default `full`) |
| `--audit-log PATH` | `up`: record control events as JSON lines (e.g. `~/.tyd/audit.log`) |
| `--session-idle-timeout D` | `up`: close sessions idle this long, e.g. `8h` (default off) |
| `--session-output-log-max SIZE` | `up`: per-session output log cap, e.g. `64MB` (default 64MB) |
| `--session-send-timeout DURATION` | `up`: how long one send may wait for the PTY, max `30s` (default `5s`) |
| `--archive-ttl D` | Hide a peer, or a closed session, unused this long: `7d`, `168h`, `off` (default `7d`; env `TYD_ARCHIVE_TTL`) |
| `--read-only` | `mcp`: register only `session_list` and `session_read`. Not a permission boundary — the daemon's capability check is |
| `--max-sessions N` | `mcp`: sessions one process holds; `0` means the default, not no limit (default 8) |
| `--close-on-exit` | `mcp`: close the sessions this process opened when it stops (default: they survive) |
| `--allow-peer REF` | `mcp`: serve this peer too; repeat for several. Required before the tools take a `peer` argument. `local` is accepted here as well |
| `--as NAME` | Peer nickname when accepting an invite |
| `--no-wait` | `register` / `invite`: print the accept line and exit |
| `--shell PATH` | `session create`: shell to run; must be listed in the **daemon's** `/etc/shells` (default: the daemon's own shell) |
| `--detach` | `session create`: print the id only |
| `--all` | `peer list` / `session list`: include archived rows |
| `--verbose` | `session create/attach/watch`: SSH-style connect debug on stderr; also reports a prune that could not write |
| `--force` | `register`: replace an existing registration (invalidates peers); `revoke` / `session rm`: delete without asking |
| `--fix` | `doctor`: rebuild a damaged `peers.json` from the Control Panel |
| `--live PATH` | `up` / `doctor`: live-agent state root (default `~/.tyd/live`) |

## State directory

Everything lives under `~/.tyd`:

| Path | Contents |
|------|----------|
| `tyd.sock` | Unix socket (CLI ↔ daemon) |
| `id_ed25519`, `id_ed25519.pub` | Identity (private key mode `0600`) |
| `trusted.json` | Bootstrap trust: public keys and capabilities |
| `peers.json` | Paired peers; a cache of what the daemon already holds |
| `aliases.json` | Client-local session names |
| `recent.json` | Last peer / session used by this client |
| `sessions.json` | Client-local session catalog read by `session list` and by `tyd mcp`'s `session_list` |
| `archive.json` | Which peers and sessions are archived, and when each peer was last dialled. Kept out of `peers.json` on purpose: that file is rebuilt from the Control Panel on every sync, and `doctor --fix` replaces it outright |
| `live/<id>/` | Per-session live-agent socket, metadata, PID, and sequenced output segments (`output.<seq>`, `0600`; deleted on close) |
| `audit.log` | Only when `--audit-log` points here |
| `tyd.log`, `tyd.pid` | Written by the `nohup` install fallback |

## Peer and session targeting

`--peer` applies to the commands that dial a daemon: `session create`, `attach`,
`watch`, and `close`. Without it, tyd uses `recent.json` when present, else the
only outbound peer, else falls back to the local unix socket; with several
outbound peers it errors and asks for `--peer`. `session list` ignores `--peer`
and never dials.

`tyd <session>.<peer>` is the attach shortcut. The left side is a session alias
or id; the right side is a peer nickname or id. `tyd jammy.laptop` is the same
command as `tyd --peer laptop session attach jammy`. The token must contain
exactly one `.`, both sides must be non-empty, and no extra arguments are
accepted. A `--peer` flag that names a different peer is an error. Names that
themselves contain `.` stay on the long form — `tyd session alias` and
`tyd peer alias` accept such a name and warn that the shortcut cannot use it.
This shortcut only attaches; it does not watch or close.
