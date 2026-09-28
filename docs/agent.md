# Agent handbook

> Read this if you are an LLM agent operating a shell. It is the fastest way to understand tyd and to run it without asking the human.

## What tyd is

tyd keeps **persistent, remotely attachable shell sessions on a target machine**. A daemon on the target holds a PTY per session. A paired peer creates or reattaches sessions; the shell survives client disconnect and (on graceful restart) daemon restart. tyd is not an SSH dependency, not a VPN, and not a file-transfer tool.

One binary (`tyd`) does everything. `tyd up` is the daemon; every other subcommand is a client.

## Install — one line

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh
```

Per-user only, no sudo. The binary goes to `~/.local/bin` (override with `TYD_BINDIR`). The daemon runs under `systemd --user` on Linux, a LaunchAgent on macOS, otherwise `nohup`/`setsid`. Binaries are fetched from the latest GitHub Release (`tyd-<os>-<arch>.tar.gz`, one archive per platform, about 3.7MB).

Non-interactive forms — use these from an agent:

```bash
# Target machine (holds the shells): install, start the daemon, mint an invite, print one client bootstrap line
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent

# Peer machine (connects to the target): install and pair in one step
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN

# With a nickname for the peer (shown in peer list / audit log)
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN --as laptop

# Custom Control Panel
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent --platform https://cp.example.com
```

Human TTY: the script asks server vs client interactively; a server install asks whether to mint an invite now, and the client command is printed once, on stderr. Agent / no TTY: defaults to server and prints the client bootstrap line on stdout, which is the only thing written there.

Environment overrides: `TYD_PLATFORM` (Control Panel URL), `TYD_BINDIR`, `TYD_RELEASE_URL`, `TYD_INSTALL_URL`. Re-running the script upgrades in place (temp file + `mv`, so a running daemon is not blocked by `ETXTBSY`); an already-running daemon is restarted onto the new binary.

Verify:

```bash
~/.local/bin/tyd status        # or tyd status if ~/.local/bin is on PATH
tyd --help                     # authoritative flag list; this doc is the map
```

If `tyd status` says `local daemon not running; start with tyd up`, start it: `tyd up`. The `nohup` fallback writes `~/.tyd/tyd.log` and `~/.tyd/tyd.pid`.

## Tool model

```
tyd CLI ── unix / tls / quic / relay ── tyd up ── live-agent (one process per session) ── PTY ── $SHELL
```

| Layer | What it does |
|-------|--------------|
| Session / PTY | Create, I/O, resize, signal, close; each session is a `live-agent` under `~/.tyd/live/<id>/` so the shell outlives the daemon |
| AuthZ | Capabilities: global `list`/`create`, per-session `attach`/`write`/`resize`/`signal`/`close` |
| AuthN | Ed25519 challenge-response against `~/.tyd/trusted.json` |
| Protocol | Length-prefixed JSON frames over any byte stream |
| Transport | How the stream is obtained: `unix` (local), `tls` (opt-in TCP), `quic` (peer data plane), `relay` (WebSocket rendezvous fallback) |

Key facts for an agent:

- Pairing metadata (ids + peer public keys) lives on the Control Panel; TTY bytes never go through it.
- A registered `tyd up` publishes QUIC candidates to the Control Panel (ephemeral, refreshed ~30s, expiring ~90s). Clients try QUIC first, then fall back to the relay (`https://app.getfda.dev/relay` by default). No flag needed unless you want `--relay off` or a custom relay URL.
- `~/.tyd` is the entire state root (see `cli.md` / `operations.md` for the full file list). `sessions.json` is a **client-local** catalog; `tyd session list` never dials. `peers.json` is a cache of what the daemon holds in memory.

## Pairing

On the machine that holds the shells:

```bash
tyd up                      # ensure the daemon is up
tyd invite --no-wait        # mint a token (10 minute TTL), print: tyd accept <TOKEN>
# or tyd register --no-wait  (first time on a fresh daemon)
```

`register` / `invite` wait for the peer by default (TTL countdown on stderr, Ctrl-C revokes). `--no-wait` is what agents should use.

Hand the peer one line:

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept TOKEN
# or, if tyd is already installed there:
tyd accept TOKEN --as laptop
# already paired: prints that peer, exit 0 (not an error)
# peer daemon up: also prints `tyd session create --peer <nick>`
tyd status                  # shows registration, peers, recent, aliases, live connections
tyd peer list               # paired peers and nicknames
```

Revoke from either side: `tyd revoke <peer-id-or-nick>`. Re-registering an already-registered daemon needs `--force` (invalidates old peers) or a TTY confirmation.

## Sessions — what an agent actually runs

On the **client** after pairing:

```bash
tyd --peer laptop session create          # create and attach (default, interactive)
tyd --peer laptop session create --detach # create only, print the session id (for scripts)
tyd session list                          # local catalog, no network, no --peer needed
tyd session attach <id-or-alias>          # exclusive writer; Ctrl-\ detaches, shell keeps running
tyd session watch <id-or-alias>           # read-only follow; Ctrl-C stops watching
tyd session close <id-or-alias>           # kill the shell, mark CLOSED in the local catalog
tyd session alias jammy                   # name the most recent session
tyd session alias <session_id> jammy      # name a specific session
tyd session alias list
tyd session alias rm jammy
tyd jammy.laptop                          # attach shortcut: session alias . peer alias
```

Targeting: `--peer ID|NICK` applies to `session create/attach/watch/close` (the dial commands). Without it, tyd uses `~/.tyd/recent.json` when present, else the only outbound peer, else the local unix socket. `session list` ignores `--peer`.

`tyd <session>.<peer>` attaches only. `tyd jammy.laptop` is `tyd --peer laptop session attach jammy`. Exactly one dot; both sides are an alias or a raw id. It does not watch or close.

Lifecycle notes an agent must know:

- `create` attaches by default. For automation, always use `--detach` and capture the id.
- `Ctrl-\` detaches and leaves the shell running. `session close` is the deliberate end; the row stays as `CLOSED` history. A shell that exits on its own (`exit`, Ctrl-D) leaves the session `EXITED` but still attachable — the next `attach` replays the previous output and starts a fresh shell with the same id.
- Connect progress is silent; `--verbose` prints `debug1:` lines on stderr and is safe to add when debugging (`--verbose` is the only verbose flag; `-v` does not exist).
- Daemon restart: a graceful `tyd up` stop (SIGINT/SIGTERM) detaches clients and leaves live-agents running; the next `tyd up` re-adopts them and re-grants the creator's owner caps. `kill -9` is best-effort.

## Recipes

### Agent on a fresh target — bring it online and get a client one-liner

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent
# stdout is the client bootstrap line; stderr has progress. Capture stdout
# (in a TTY, stdout stays empty unless --agent is passed):
BOOTSTRAP=$(curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --agent 2>/dev/null)
echo "$BOOTSTRAP"
# then paste that curl ... --client --accept TOKEN line on the peer
```

### Agent as client — pair and open a shell

```bash
curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --accept "$TOKEN" --as ci
tyd peer list
SID=$(tyd --peer ci session create --detach)
echo "$SID"
tyd session attach "$SID"   # interactive; or drive it via expect / pexpect
```

### Drive a shell non-interactively

Prefer `--detach` + `attach` over trying to pipe into `create`. For scripted checks, `watch` dumps history without taking the writer slot:

```bash
tyd session watch "$SID"    # read-only, exits on Ctrl-C
```

## Troubleshooting for agents

| Symptom | Meaning | Fix |
|---------|---------|-----|
| `local daemon not running; start with tyd up` | `tyd status` could not dial `~/.tyd/tyd.sock` | `tyd up`; check `~/.tyd/tyd.log` if it still fails |
| `session not found` | No such id/alias/recent | `tyd session list`; check the id and `--peer` |
| `permission denied` | Session exists but this identity lacks the cap | Pair correctly; check `~/.tyd/trusted.json` and `peers.json` |
| `untrusted public key` / `untrusted server certificate` | AuthN or TLS pin mismatch | Re-pair; or copy the server's `server.crt` and pass `--tls-cert` with `--addr` |
| `attach pending approval` | Daemon is in `pre` approval mode | On the target (unix socket): `tyd session approve <id>` |
| Dual NAT, direct dial fails | Both sides behind NAT with no public IP | Ensure `tyd up` is running (publishes candidates) and the relay is reachable; avoid `--relay off` |
| Disk full | State writes go to temp + rename; memory stays authoritative | Free disk, then `tyd doctor` / `tyd doctor --fix` |

Useful introspection:

```bash
tyd status                  # registration, peers, aliases, live connections (needs daemon + list cap)
tyd peer show <id|nick>     # endpoint and reachability
tyd doctor                  # state files and free space; --fix rebuilds peers.json from the Control Panel
tyd --help; tyd session help; tyd peer help   # authoritative
```

## What not to do

- Do not run the install script with `sudo` — everything is per-user.
- Do not put TTY bytes through the Control Panel — the relay is a blind WebSocket splice; session bytes are end-to-end.
- Do not treat `sessions.json` as server-side truth — it is client-local and advisory.
- Do not use `tyd create` / `tyd list` — they are rejected; use `tyd session create` etc. (`tyd alias` still works but prints a deprecation note; prefer `tyd session alias`).

## Where to read more

- `connect.md` — install, pair, connect, detach/close, dual NAT
- `session.md` — lifecycle, aliases, approval modes, audit log
- `operations.md` — daemon flags, data plane, Docker/Compose, recovery, `tyd doctor`
- `cli.md` — full command and flag reference (help is still authoritative)
- `overview.md` — architecture and non-goals
- `protocol.md` — frame protocol and auth handshake
