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
- A registered `tyd up` publishes QUIC candidates to the Control Panel (ephemeral, refreshed ~30s, expiring ~90s). Clients try QUIC first, then fall back to the relay (`https://app.getfda.dev/relay` by default). No flag needed unless you want `--relay off` or a custom relay URL. A Control Panel that restarts and loses its registrations is noticed and repaired by the daemon itself on the next round, so deploying one does not mean bouncing `tyd up` on every host.
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

Do not pipe into `create`, and do not reach for `expect` or `pexpect`. A session
has a writer slot and a recorded output stream, and there are commands for both.

```bash
SID=$(tyd --peer laptop session create --detach)   # open, print the id, attach nothing

tyd --peer laptop session send "$SID" 'make test
'                  # type into it; nobody may be attached at the same time
tyd --peer laptop session read "$SID" --wait 2s   # read what those keystrokes printed
tyd --peer laptop session watch "$SID"            # read-only follow, Ctrl-C stops
tyd --peer laptop session close "$SID"
```

`send` writes and then reads on one connection, so a `send` already returns the
output it caused. Use `read` for the next page, by cursor, and `watch` to follow
along. `send` is refused while a person is attached, which is how a model and a
human avoid fighting over one shell.

A model gets the same thing over MCP instead of a shell — see
[Let a model drive it](#let-a-model-drive-it-mcp) below.

Traps an agent should know about:

- `send` has a size cap and refuses anything over it rather than splitting. Send
  a file in pieces, or write it on the target with a shell command.
- `send` types bytes as they stand. Backslashes are literal unless you ask for
  escapes, so a regex or a `sed` script is not mangled by default.
- `send timed out` means the PTY did not accept the bytes in time. The written
  count in the error says how many landed. **Read before resending.**
- If the socket path is too long for `AF_UNIX`, the daemon refuses to start. The
  limit is about 100 bytes; `tyd doctor` reports it.

## Let a model drive it (MCP)

`tyd mcp` speaks the Model Context Protocol over stdio, so a model uses a tyd
session the way a person uses a terminal: open a shell, type into it, read what
it printed, stop a command, close it.

### Install — one line

```bash
claude mcp add tyd -- "$(command -v tyd)" mcp --peer laptop
```

**Use the absolute path `command -v tyd` prints.** Many MCP clients launch the
command without a login shell, so `~/.local/bin` is not on `PATH` and a bare
`tyd` is not found. That shows up as the client reporting the server failed to
start. Substitute your own path; `/usr/local/bin/tyd` is not where tyd has to be.

The same thing in the JSON most clients read:

```json
{
  "mcpServers": {
    "tyd": {
      "command": "/usr/local/bin/tyd",   // whatever `command -v tyd` prints
      "args": ["mcp", "--peer", "laptop"]
    }
  }
}
```

### The target is always named

`--peer <id|nick>` chooses the machine, and it is not optional by accident. With
one paired peer it may be left off, because there is only one answer. With none,
tyd **refuses to start** rather than fall back to the machine the model runs on:
that daemon holds the shells you are sitting at, and it does not ask for
approval the way a remote peer does. Pass `--peer local` for this machine.

Every result names the machine it ran on:

```
[tyd: target=laptop reason=match state=running]
```

Startup prints the same thing on stderr, so a mistake is visible before the first
tool call.

### The tools

| Tool | What it does |
|------|--------------|
| `session_open` | Creates a session **without** attaching, names it, returns its first output. `shell` picks the shell; `name` sets the alias a person attaches by |
| `session_list` | The local catalog plus a probe read per session, so the state is what the target says rather than what a file remembers |
| `session_send` | Types into a session nobody is attached to, and returns what those keystrokes printed |
| `session_read` | Reads from the last cursor, or from one you name |
| `session_interrupt` | Sends Ctrl-C to whatever is running |
| `session_close` | Ends a session |

`--read-only` registers only `session_list` and `session_read`. `--close-on-exit`
closes what this process opened; without it the sessions outlive the server, so a
model can come back to the same shell.

### A person can always take over

Every `session_open` returns a command the model can hand to you:

```
[tyd: target=laptop ...]
[a human can take this session over with: tyd build.laptop]
```

You attach, the model's next `session_send` is refused with `session in use` and
told to retry, and once you detach with `Ctrl-\ ` it works again. The refusal
names the reason rather than failing silently, so a model reports "someone is
attached" instead of "the target is broken".

### Security boundaries — read these before exposing it

- **`--read-only` is not a permission boundary.** It only stops the write tools
  from being registered. The real boundary is the capability the daemon grants
  that peer: re-pair with fewer capabilities, or approve mode `pre`, and the
  daemon is what refuses.
- **Terminal output is untrusted data.** Anything a session prints is data, not
  instructions, and it is fenced in the result for that reason. A prompt can
  contain text that looks like a command.
- **A password typed into a session is in that session's log.** The result warns
  when the last line looks like a password prompt, because the PTY's echo state
  is not reported yet. Do not type secrets; hand the session to a person.
- **While a person is attached, the model can still read** what the terminal
  shows, including anything typed with echo off is *not* visible — but a password
  prompt's surroundings are.
- **A cancelled `send` is not a finished `send`.** If a call is withdrawn after
  the bytes were written, the next call on that session says so: the keystrokes
  are in and the command may already have run. Read before resending.
- **A target in `pre` approval mode approves one request at a time.** `send` and
  `read` are both reviewed, so every call needs its own `tyd session approve
  <id>` on the target. That is the daemon's rule, not a tyd mcp one; against a
  `pre` target expect to ask for approval per call, or pair a dedicated identity
  and use `--approval full` for it.

### Versions

The **target's daemon** has to be new enough too: `send` and `read` are daemon
side RPCs, so an old `tyd up` rejects them. Check the target with `tyd status`,
and use a release that contains `send` / `read` — or build both sides from
`main` until one does.

A model that meets a `send` / `read` it does not recognise is told the target is
too old and to upgrade, rather than being left to guess.

### Giving an agent its own identity

Pair the agent separately, with a name you would recognise in `peer list` and the
audit log, and revoke it when the work is done:

```bash
tyd accept "$TOKEN" --as build-agent    # on the model machine
tyd revoke build-agent --force          # when it is finished
```

It gets its own entry in `paired.json` and can be revoked without touching the
pairing you use yourself.

## Troubleshooting for agents

| Symptom | Meaning | Fix |
|---------|---------|-----|
| `local daemon not running; start with tyd up` | `tyd status` could not dial `~/.tyd/tyd.sock` | `tyd up`; check `~/.tyd/tyd.log` if it still fails |
| `session not found` | No such id/alias/recent | `tyd session list`; check the id and `--peer` |
| `permission denied` | Session exists but this identity lacks the cap | Pair correctly; check `~/.tyd/trusted.json` and `peers.json` |
| `untrusted public key` / `untrusted server certificate` | AuthN or TLS pin mismatch | Re-pair; or copy the server's `server.crt` and pass `--tls-cert` with `--addr` |
| `attach pending approval` | Daemon is in `pre` approval mode | On the target (unix socket): `tyd session approve <id>`. The approval covers one request, so a model needs one per `send` / `read` |
| `this machine has no outbound peers` | `tyd mcp` with no `--peer` and no paired peer | Pass `--peer local` for this machine, or `--peer <id|nick>` |
| `not a paired peer on this machine, and not "local"` | `--peer` named something that is not paired here | `tyd peer list`; pair first, or use `--peer local` |
| The MCP client reports the server failed to start | A bare `tyd` was not on the client's `PATH` | Use the absolute path: `claude mcp add tyd -- /usr/local/bin/tyd mcp --peer laptop` |
| `read is not supported on in-process sessions` | A session whose shell runs inside the daemon rather than as a live-agent | Restart the daemon so it adopts the session as a live-agent (`tyd up`) |
| `send timed out` | The PTY did not accept the bytes in time | The error carries the written count. Read the session before resending; do not send the whole thing again |
| `socket path too long` | The state directory is deep enough to overrun `AF_UNIX` | Move `~/.tyd` shallower (`--socket`, `--live`); `tyd doctor` reports it |
| `the target is too old to know send/read` | The target's `tyd up` predates those RPCs | Upgrade the target's daemon, not just the client |
| `session in use` | A person is attached to the session | Ask them to detach with `Ctrl-\ `, or wait. Reading still works |
| Dual NAT, direct dial fails | Both sides behind NAT with no public IP | Ensure `tyd up` is running (publishes candidates) and the relay is reachable; avoid `--relay off` |
| `tyd cp: the Control Panel had forgotten this daemon; restored registration <id>` | The Control Panel restarted; its in-memory state went with it | Nothing — the daemon re-registered and republished its endpoint in the same round. Sessions survive; a client mid-session reconnects on the next `attach` |
| `cp maintenance: cp re-register: …` on the target | A restart was followed by a failed restore (usually the Control Panel still down) | It retries on a 30s→1m→2m→5m backoff. Check the Control Panel, then `tyd peer show <id>` — the relay carries traffic meanwhile |
| Disk full | State writes go to temp + rename; output log degrades to the ring; memory stays authoritative | Free disk, then `tyd doctor` / `tyd doctor --fix` |

Useful introspection:

```bash
tyd status                  # registration, peers, aliases, live connections (needs daemon + list cap)
tyd peer show <id|nick>     # endpoint and reachability
tyd doctor                  # state files, free space, output-log write failures; --fix rebuilds peers.json
tyd --help; tyd session help; tyd peer help   # authoritative
```

## What not to do

- Do not run the install script with `sudo` — everything is per-user.
- Do not put TTY bytes through the Control Panel — the relay splices a WebSocket, and the two peers run TLS 1.3 inside it, so it carries ciphertext. It still sees connection metadata.
- Do not treat `sessions.json` as server-side truth — it is client-local and advisory.
- Do not use `tyd create` / `tyd list` — they are rejected; use `tyd session create` etc. (`tyd alias` still works but prints a deprecation note; prefer `tyd session alias`).
- Do not give a model `tyd mcp` without `--peer` and expect it to be safe on its own — `--read-only` is a hint to the model, not a control on the daemon.
- Do not type a password into a session a model can read. Hand it over with the attach command the result prints.

## Where to read more

- `connect.md` — install, pair, connect, detach/close, dual NAT
- `cli.md` — `tyd mcp` flags and the full command reference
- `session.md` — lifecycle, aliases, approval modes, audit log
- `operations.md` — daemon flags, data plane, Docker/Compose, recovery, `tyd doctor`
- `cli.md` — full command and flag reference (help is still authoritative)
- `overview.md` — architecture and non-goals
- `protocol.md` — frame protocol and auth handshake
