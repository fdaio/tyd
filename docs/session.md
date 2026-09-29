# Sessions

Everything under `tyd session` operates on a session id, an alias, or — when the
id is omitted — the most recent session (`~/.tyd/recent.json`).

```bash
tyd session help          # the authoritative subcommand list
```

## Lifecycle

```bash
id=$(tyd session create --detach)  # create only, print the id (for scripts)
tyd session create                 # create and attach (default)
tyd session list                   # local catalog
tyd session attach jammy           # interactive; Ctrl-\ detaches
tyd session watch jammy            # read-only follow / history dump
tyd session close jammy            # kill the shell; catalog marks CLOSED
```

`create` attaches unless `--detach` is given. Local unix targets start `tyd up` on
demand when the socket is not listening; peer and `--addr` targets never start a
local daemon.

`attach` takes the exclusive writer slot; a second attaching client is rejected.
`watch` is read-only and does not take that slot, so you can follow a session
someone else is typing in.

### The catalog is local

`tyd session list` never dials: it merges `~/.tyd/sessions.json` with aliases and
the recent placeholder, and ignores `--peer`. Create writes the catalog (including
the dial address when known); attach and close reuse that address. A stale cached
address is refreshed from the Control Panel and retried once.

```
SESSION    ALIAS   PEER    STATE     CREATED
a1b2c3     jammy   laptop  ATTACHED  2026-09-26 10:04
c7d8e9     -       -       EXITED    2026-09-26 10:02
d4e5f6     -       -       CLOSED    2026-09-26 09:58
```

A session id is an opaque token the daemon mints, never a name. When a
command resolves a reference it cannot recognise — the user typed
`tyd session attach work-laptop` and no such session is known — the dial still goes
ahead, but the name is not remembered as a session id, and a catalog row whose
id is not a session id is dropped on the next read. Such a row can otherwise
block the name as an alias forever.

Alive sessions come first (`ATTACHED`, `EXITED`, `PENDING`, `DETACHED`), then
closed ones; newest first inside each group.

### Detach, watch, close

| Action | Effect |
|--------|--------|
| `Ctrl-\` (attach) | Detach; PTY and shell keep running |
| `Ctrl-C` / `Ctrl-\` (watch) | Stop watching; session unchanged |
| Client crash or socket drop | Same: the session stays |
| `exit`, Ctrl-D, shell crash or kill | Shell goes away; session becomes `EXITED`, still attachable |
| `tyd session close <id>` | Kill the shell; mark `CLOSED` in the local catalog |

Connect progress is silent by default. `--verbose` prints SSH-style `debug1:`
lines on stderr (resolve → dial → attach) for `create` / `attach` / `watch`.
Ctrl-C cancels before the session is live. Each dial candidate gets about 12
seconds for connect, TLS, and auth.

### The shell can exit; the session does not

Running `exit` (or Ctrl-D, a crash, or a kill) inside a session ends only the
shell. The session is **not** closed — it becomes `EXITED` and stays
attachable:

```
$ tyd session attach jammy
$ exit
[tyd] shell exited (status 0) — session still attachable; attach again for a new shell
$ tyd session attach jammy          # same session id, a brand new shell
```

`logout` is not in that list on purpose: it only ends a login shell, and tyd
starts the shell as a plain interactive one, so use `exit` or Ctrl-D.

`attach` on an `EXITED` session starts a fresh shell with the same shell program,
working directory, and window size, replaying the recorded output first, so you
still see what the previous shell printed. `watch` on an `EXITED` session prints
the notice and stops.

A session ends in exactly two ways: `tyd session close`, or
`--session-idle-timeout` (see below). Nothing else ends one — not detaching, not
the shell exiting, and not restarting the daemon. `tyd up` re-adopts every
surviving live-agent, and a session whose shell is gone comes back as `EXITED`.
Retiring a session is therefore a deliberate `tyd session close`; the row stays in
the client catalog as history, because that catalog is client-local and outlives
the daemon.

### Aliases

Aliases are **client-local** names for sessions — not peers — stored in
`~/.tyd/aliases.json`.

```bash
tyd session alias jammy              # name the most recent session
tyd session alias <session_id> jammy # or name a specific one
tyd session alias set <session_id> <name>
tyd session alias list
tyd session alias rm <name>
```

A name that collides with an existing session id or alias is rejected. The older
top-level `tyd alias` still works but prints a deprecation note.

A name may contain a dot, and it is stored either way — but a dot costs the
shortcut below, so setting one says so:

```console
$ tyd session alias 0123456789abcdef tama.cp
tama.cp -> 0123456789abcdef
warning: session alias "tama.cp" contains a '.', so `tyd <session>.<peer>` cannot use it; use tyd session attach tama.cp
```

With a peer nickname, attach in one token: `tyd <session>.<peer>`. If the
session alias is `jammy` and the peer nickname is `laptop`, `tyd jammy.laptop`
attaches to that session. It is the same as `tyd --peer laptop session attach jammy`.
Each side may also be a raw id. The token needs exactly one dot. See
[cli.md](cli.md).

## Approval modes

The daemon enforces the approval mode stored in `peers.json`. Set it at register
time or change it later without re-registering:

```bash
tyd register --approval full|pre|post
tyd approval                 # print the current mode
tyd approval pre             # switch; keeps the daemon id and all pairings
```

`tyd approval` updates the Control Panel and `peers.json`; restart `tyd up` to
apply. If the Control Panel is unreachable the mode is still saved locally,
because the daemon is what enforces it.

| Mode | Behavior |
|------|----------|
| `full` (default) | Remote create starts a shell immediately |
| `post` | Same as `full`, plus control events are audited |
| `pre` | Every remote create, attach, and watch waits for a local decision |

Under `pre`, "remote" means any non-unix transport — TLS and QUIC alike. Local
unix-socket work bypasses the gate, because that is the operator.

```bash
# On the machine running the daemon (unix socket):
tyd session list            # PENDING sessions appear in the alive group
tyd session approve <id>    # starts the PTY → DETACHED
tyd session reject <id>     # removes the pending session
```

A remote attach or watch under `pre` is refused with `attach pending approval` and
recorded as a waiting request; the same `tyd session approve <id>` releases it.
**Approvals are one-shot**: approving a create also covers the attach that
immediately follows, but every later reattach is reviewed again, so access never
becomes permanent. Requests and approvals expire after 10 minutes.

`approve` and `reject` are accepted only over the local unix socket, never over
TLS or QUIC.

## Audit log

Auditing is independent of the approval mode — any mode can write it:

```bash
tyd up --audit-log ~/.tyd/audit.log
```

One JSON object per line, file created `0600`, appended across restarts:

```json
{"time":"2026-09-18T03:11:52Z","event":"attach_pending","session_id":"a1b2","principal":"laptop","transport":"quic","approval_mode":"pre"}
```

Events: `create`, `create_pending`, `approve`, `reject`, `attach`,
`attach_pending`, `detach`, `close`, `idle_close`, `denied`. Records carry
metadata only — terminal input and output never enter the log, and nothing is
sent to the Control Panel. Without `--audit-log`, `post` mode still writes the
same records to stderr, and `full` / `pre` write nothing.

## Idle sessions

With no idle timeout, a session lives until you `tyd session close` it. To
expire unattended ones:

```bash
tyd up --session-idle-timeout 8h   # default: off
```

A session counts as idle from the moment the last client detaches — or, if its
shell exited, from the moment the shell went away; attaching resets the clock.
`PENDING` sessions are never reaped — they wait for you.

## Who may do what

`attach` does not imply `write`. A key granted only `attach` can follow output
(via `attach` or `watch`) but cannot type. An identity with `create` receives
owner caps (`attach`, `write`, `resize`, `signal`, `close`) on the session it just
created — in the running daemon's memory, re-derived on restore, never written
back to `trusted.json`. The trust file format is in
[operations.md](operations.md).
