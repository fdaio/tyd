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
tyd session rm jammy --force       # forget a closed session locally
tyd session list --all             # include archived sessions
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
| `tyd session rm <id> --force` | Forget a `CLOSED` session in the local catalog; the daemon is not contacted |

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

### Removing and archiving a session

`session close` ends a session. Two more commands deal with the row it leaves
behind.

`tyd session rm <id|alias> --force` forgets a `CLOSED` session in the local
catalog. The row holds the endpoint, so `rm` refuses a session that is not closed
— and `--force` does not change that, because the fix is to close it, not to
delete the address. The daemon keeps the session until it restarts, and any
alias for the session goes with it, because a leftover alias would merge the row
straight back into the list.

`--archive-ttl` hides sessions nobody has touched. It defaults to `7d` and takes
`7d`, `168h`, or `off`; `TYD_ARCHIVE_TTL` sets it for the whole host and
`--archive-ttl` wins for one command. Only a `CLOSED` session is a candidate, and
the clock runs from the close — or from a later read, if there was one. A session
that is `PENDING`, running, or `EXITED` is never archived, because it can still be
attached.

Archiving is a display state, not a deletion: nothing is removed from
`sessions.json`, the daemon is untouched, and `tyd session restore` puts the row
back. `session list` hides archived rows and says how many it hid; `--all` shows
them, marked `(archived)`. Reading or driving a session puts it back on its own.
The marks live in `~/.tyd/archive.json` rather than in `sessions.json`, so a
catalog rebuild cannot drop them, and a prune that cannot write is skipped in
silence rather than failing the command.

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

A remote request under `pre` — create, attach, watch, read or send — is refused and
recorded as a waiting request, and the daemon prints what it is waiting for:

```
tyd approval needed: alice wants to send 9 bytes to 0de1337a [98c250848311] (tyd session approve 0de1337a)
```

That line is the whole approval. It names the operation, the size and the session,
and **never the content**: a `send` shows how many bytes, not what they are. The
bracketed value identifies the request if more than one is waiting.

**Approvals are one-shot and bound to one request.** An approval is spent only by
the request it was granted for — the same operation, on the same session, with the
same byte count. It does not carry to the next request, and it does not carry
across kind. So approving a `create` does **not** release a later `send`, and an
approval given for a `read` cannot be spent by a `read` the peer chose afterwards.

That is deliberate. The alternative — approving a session, so that whatever arrives
next is allowed — means the thing that runs is not necessarily the thing you were
shown, and on a busy session the gap between the two is where an accident would
land.

Two consequences worth planning for:

- **Requests expire after 10 minutes**, approvals included, so a decision made late
  is not spent on something that happened after it.
- **A `send` needs two approvals** to be worth anything: one for the write, one for
  the read that would report its output. Under `pre`, a model is impractical on
  purpose — pair a dedicated identity against a daemon registered `--approval full`.

### When more than one request is waiting

`tyd session approve <id>` approves the request that is waiting. If several are, it
refuses rather than picking one for you:

```
session 0de1337a has 2 requests waiting for approval, so approving all of them
would decide requests you were not shown. Name the one you mean:
  98c250848311  read 0de1337a  (alice)
  c41d09bb7e20  send 9 bytes to 0de1337a  (alice)

  tyd session approve 0de1337a --digest <hex>
```

Identical requests share one waiting record, so a peer retrying does not fill the
list with copies. The number of distinct requests that can wait at once is bounded,
so a peer cannot bury you: past the limit the request is refused and the ones
already waiting are the ones you were going to look at.

`approve` and `reject` are accepted only over the local unix socket, never over
TLS or QUIC. The approving client must send a handshake version; one that does not
is refused with an upgrade message, because a client too old to name a request
cannot be allowed to approve all of them.

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
`attach_pending`, `detach`, `close`, `idle_close`, `denied`, `read`, `send`.
`send` records the byte count and never the bytes.
`read` is recorded only when the reply broke the reader's view of the stream:
`reason` is `cursor_reset` (the cursor was reset, so the reader lost its
place) or `dropped_prefix` (the requested prefix was already gone). Ordinary
paging is not recorded, because draining the output log is a thousand calls.
Records carry metadata only — terminal input and output never enter the log,
and nothing is sent to the Control Panel. Without `--audit-log`, `post` mode
still writes the same records to stderr, and `full` / `pre` write nothing.

## Idle sessions

With no idle timeout, a session lives until you `tyd session close` it. To
expire unattended ones:

```bash
tyd up --session-idle-timeout 8h   # default: off
```

A session counts as idle from the moment the last client detaches — or, if its
shell exited, from the moment the shell went away; attaching resets the clock.
`PENDING` sessions are never reaped — they wait for you.

## Output log and `read`

Live-agents keep a sequenced copy of PTY output on disk so a client can resume
after a disconnect without taking the writer slot:

- Seq is a byte offset from 0 for the life of the session. An agent restart
  continues from the files already in `~/.tyd/live/<id>/`. Output produced
  while the agent was dead is gone and cannot be recovered.
- `read` flushes pending bytes before it replies, so a `kill -9` of the
  live-agent does not leave a client cursor past disk. A power loss (or a
  disk-full hole) still can. The next agent treats a missing `output.clean`
  as an unclean restart and bumps `epoch`. A stale epoch still serves
  cursors inside the previous durable end; a cursor past that bound returns
  `cursor_ahead`. Resume from `cursor_next` with the new `epoch`; do not
  keep the old cursor, or later writes at those offsets will look like the
  missing bytes.
- Disk full: the PTY stays on the 64KB ring and `seq` still advances.
  Live `read` can return those ring bytes; they are not on disk. After
  restart, a cursor in that range is `cursor_ahead`. `tyd doctor` reports
  `output.err`.
- `attach` and `watch` are unchanged: exclusive writer, 64KB ring replay.
- `tyd session send <id> 'echo hi\n'` types into a session without the attach
  slot. It refuses while someone is attached, and never starts a shell.
- `tyd session read <id> --follow` streams until the shell exits; `--wait` holds
  one page open until bytes arrive. Under `pre` each page needs its own
  approval, so `--follow` is impractical there.
- `read --until-match REGEX`, `--until-idle D` and `--max-bytes N` wait for a
  condition instead of for any data. `--json` reports which one fired in
  `reason`. `send --json` reports the cursor it wrote at, so a script can read
  only the output its own command produced.
- `read` is a non-blocking page (64KB max) with `cursor` / `cursor_next`.
  Holding `attach` can now retrieve up to the disk cap (default 64MB), not
  only the ring. That is still "can see the terminal"; it is a larger window.
- Files are mode `0600`, deleted on `session close`, and never written into
  `--audit-log`. `--session-output-log-max SIZE` on `tyd up` changes the cap.
- `session create --shell PATH` chooses the shell. It is checked against the
  **daemon's** `/etc/shells`, not the client's: with `--peer` the client may be
  on another host, where that file says nothing about the one that will start
  the session. An unlisted shell is refused with a message naming the shell and
  the file. Leaving the flag off uses the daemon's own shell, which is not
  subject to the check, so an empty or unreadable `/etc/shells` does not stop
  sessions from starting. This is a typo guard, not a sandbox: anyone who can
  create a session can already run the default shell.
- A send is bounded. It gives up after `--session-send-timeout DURATION`
  (default `5s`, capped at `30s`) and the reply is `send timed out` with the
  number of bytes that reached the PTY. Nothing is written after that point,
  so a retry resumes from the reported count. `attach` preempts a send in
  progress, which fails as `preempted`; a second concurrent send is refused
  with `session busy: a send is in progress` rather than queued. An `attach`,
  `watch`, `read`, `close`, `resize` or `signal` never waits for a send.

`tyd session read` and `tyd session send` are the CLI for these frames. They
hold no state: the caller keeps `cursor` and `epoch` and passes them back. In
both, `--json` is for `read` only. In-process sessions (no live-agent) return
an explicit error.

`send` needs `write` and `read` needs `attach`, so a key that can type cannot
see the answer, and a key that can see cannot type. They are granted
separately on purpose.

## Who may do what

`attach` does not imply `write`. A key granted only `attach` can follow output
(via `attach`, `watch`, or `read`) but cannot type. An identity with `create` receives
owner caps (`attach`, `write`, `resize`, `signal`, `close`) on the session it just
created — in the running daemon's memory, re-derived on restore, never written
back to `trusted.json`. The trust file format is in
[operations.md](operations.md).
