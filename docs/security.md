# Security boundaries

tyd hands a shell to a remote peer. This page says what stands between that peer
and the machine, and — more importantly — what does not.

It is written for the case that matters: **code you are running inside a tyd
session**. If you do not trust what runs in that session, approval modes and
audit logs will not save you. Read [The local
boundary](#the-local-boundary) first.

## What tyd protects against

| Threat | Protection |
|---|---|
| A remote peer attaching without being reviewed | Approval mode `pre`; every later remote look is reviewed again |
| A peer you revoked reconnecting | The revocation is recorded locally; the Control Panel cannot re-grant it ([pairing](protocol.md#relay-path-security)) |
| The Control Panel reading your session | The data plane is TLS 1.3, negotiated between the peers. The Control Panel is a courier. |
| The Control Panel substituting a peer | Pairing is anchored to a secret it never sees; it may withdraw trust, never grant it |
| The Control Panel rewriting where a peer lives | Published endpoints are signed by the peer and verified before dialling |
| A relay reading or altering a session | Inner TLS plus a channel binding over the TLS exporter; a relay that re-terminates TLS is refused |
| A compromised paired peer logging in as you elsewhere | The login signature covers the channel binding of the connection it was made on, and the client refuses to sign a challenge that is not a nonce |
| A modified audit record going unnoticed | Records form a hash chain; `tyd audit` checks it and names the break |

## The local boundary

A session runs as **the same user as the daemon**, in the same home directory:

```
~/.tyd/id_ed25519     the daemon's identity — what a peer trusts
~/.tyd/trust.json      who may create and attach
~/.tyd/paired.json     the pairing records trust comes from
~/.tyd/peers.json      rebuilt from the Control Panel on every sync
~/.tyd/audit.log       who created, attached to, and closed what
~/.tyd/tyd.sock        the local socket every control command travels over
```

So anything running in a session — including an agent you pointed at it — can
already:

- read the identity key, and act as this daemon anywhere else;
- read and rewrite the audit log, and `peers.json` with it;
- connect to the local socket, where it authenticates **as the daemon itself**,
  because it shares `$HOME` and therefore the key;
- approve its own pending request, or set the approval mode to `full`;
- stop the daemon.

**Approval modes and audit logs are not a boundary against local code.** They
record what happened and they gate a remote peer. They do not, and cannot, make
an untrusted process on the same account safe.

## What tyd does about it anyway

Two speed bumps, neither a boundary:

- **A session's shell is marked.** `TYD_SESSION` and `TYD_PEER` are set in its
  environment, and control commands — `session approve`, `session reject`,
  `approval`, `revoke`, `invite`, `accept`, `register`, `up` — refuse to run when
  they see it. Read-only commands (`session list`, `peer list`, `status`) still
  work, because an agent legitimately needs them.
- **The connection's origin is checked.** On Linux the daemon reads the peer pid
  of a unix connection from the kernel (`SO_PEERCRED`) and walks its parent
  chain; a connection from inside a session's process tree may read but not
  change anything. On macOS the kernel reports the peer's user rather than its
  pid, so only the marker applies there.

Both are defeatable: a process can clear the variable, or leave the process tree
with `setsid` and a double fork. They exist so that the obvious move fails with
an explanation, not so that a determined one cannot happen.

The `unix` socket is where this shows up in the login signature. Every other
transport signs the channel binding of its TLS session, so a signature made on
one connection cannot be presented on another; the socket has no TLS session,
so its signature covers no binding. That costs nothing here: a process on this
account already holds the identity key, so a login it can forge buys it
nothing.

## The audit log

`--audit-log PATH` writes JSON Lines, 0600, in the daemon user's home. Each
record carries the hash of the one before it:

```
$ tyd audit
audit log ~/.tyd/audit.log: 3 record(s), chain intact

$ tyd audit          # after someone edits line 2
audit log ~/.tyd/audit.log: CHAIN BROKEN at line 2
  record contents do not match its hash
  1 record(s) checked before the break
```

What that buys, precisely:

- an edit, a deletion, or a splice **inside** the log is detected, and the
  break is located;
- a log written by an older tyd, before chaining, is reported as unverifiable
  rather than quietly passed;
- **deleting the whole file and starting a fresh chain is not detected.** The
  new log verifies perfectly. Only a copy the daemon user cannot reach catches
  that, and tyd has nowhere to put one by default.

Audit records are metadata: who did what, when, over which transport. Terminal
input, terminal output and process environment are deliberately never written
to `--audit-log`. Live-agents keep a separate per-session output log under
`~/.tyd/live/<id>/` for sequenced `read` (mode `0600`, deleted on close). That
file is not the audit chain and is not hash-chained.

A principal that holds `attach` on the session can call `read` and retrieve
up to that on-disk window (default 64MB), not only the 64KB ring that
`attach` / `watch` replay. Treat that as the same "can see the terminal"
right, with a larger history.

The **write** capability is now enough on its own to inject keystrokes, via
`send`, and it can do so **without being able to read anything back**: `send`
needs `write`, `read` needs `attach`, and the two are granted separately. A
peer that can type but not see is blind input, which is a different and
arguably more dangerous capability than "can read a terminal". Grant `write`
only to peers that would also get `attach`.

`send` refuses to run while someone holds the exclusive attach slot, so two
writers never interleave. It never starts a shell: a session whose shell has
exited is refused, so `send` cannot run a command nobody asked it to run.
Under `pre`, `send` is gated exactly like `read` and the approval is spent
once per call.

`read` can also be given a wake condition: wait for output to go quiet
(`idle_ms`), for a pattern to appear (`match`), or for a number of bytes to
accumulate (`max_bytes`). Two limits are worth knowing. A cursor that lands in
the middle of an escape sequence can leave a few stray bytes at the start of
the window, because the cleaner has no way to know what the bytes before the
cursor were doing. And matching is unreliable for full-screen programs
(`vim`, `top`, `less`), which paint the screen themselves; a condition may
never fire there, so always give `wait_ms` a bound.

In `post` mode the audit log covers control events only. **It does not record
what ran in the session.** A `send` is recorded as a control event carrying
the byte count and never the bytes. The output log does hold terminal bytes
for `read`; treat the session dir as sensitive, the same way you treat the PTY
itself.

### A secret only stays secret if the terminal is not echoing

The PTY's echo state is what decides this, and nothing in tyd reports it. A
secret typed where the terminal **is** echoing is written to the terminal
immediately, and from there into the shell's scrollback and the session's output
log, which is mode `0600` and deleted when the session closes. A shell asked for
a password switches the terminal to no-echo first, so the secret never appears —
but a secret typed at an ordinary prompt, or pasted into one, is echoed like any
other keystroke.

So a session is not a place to type a secret unless the program in front of it
turned echo off. `tyd mcp` warns when the last line of a result looks like a
password prompt, and that warning is a regex over the text: it can miss a prompt
that asks in other words, and it fires on a prompt that was never going to
receive input. The reliable answer is to hand the session to a person with the
attach command the result prints.

### A secret only stays secret if the write is refused, not warned about

The PTY echoes whatever is written to it unless the program in front turned echo
off. So a secret typed into a session reaches the terminal, the shell's scrollback
and the session's output log — and the output log cannot be redacted afterwards,
because an echoed byte and ordinary program output are indistinguishable.

`session_send` therefore takes `secret: true`, and the **target** decides: the write
is refused unless the terminal is not echoing at the moment the bytes go in. The
refusal is the point. A warning would leave the model holding a promise it cannot
check, and the one thing a caller must never infer from a terminal it could not
read is that it is safe.

There are three refusals, because the answers differ:

| State | What it means | What to do |
|---|---|---|
| echo on | the bytes would be recorded | do not send it as a model |
| raw mode | a full-screen program or a nested terminal; the far end cannot be seen | hand the session to a person |
| unreadable | the state could not be read at all | hand the session to a person |

Raw mode is the common case on a real shell rather than an edge: a non-interactive
`/bin/sh` reading commands from a PTY disables echo outright, so `secret: true` is
refused against one. That is the accepted cost — the alternative is promising
something unverifiable.

`session_read` reports `tty: {echo, icanon}` and the `input_mode` derived from
them. Both bits are reported raw as well as derived, so that a derivation found
wrong is a change of derivation and not a change of contract. Where the target
reported nothing, the result says so rather than carrying two false bits, which
would read as "not echoing".

**The write is refused unless the agent is known to honour the request.** The
dataplane between a daemon and a live agent has no handshake, and an agent older
than this flag would ignore it rather than refuse — so the bytes would land in the
clear. The agent stamps its version on what it sends, and a `secret: true` write is
refused until a reply has shown an agent new enough. An ordinary keystroke is never
gated on this, so a rolling upgrade does not stop models typing at all.

### A name is rendered into a command a person is asked to run

`tyd mcp` puts a takeover command in every result that needs one — *"ask the user
to run `tyd session attach build`"* — and a peer nickname becomes part of the same
command. So an alias or nickname is not a label, it is text that will land in
somebody's shell.

Both accept letters and digits in any script, plus `-`, `_` and `.`, and refuse
everything else. A backtick or `$( )` is one word to a shell's parser and still
substitutes, so allowing them would let anything that can influence the model's
choice of name — which includes anything whose output the model reads — reach a
person's terminal as something to paste. Refusing whitespace and `/` alone is not
enough: `id`, `whoami` and `env` need neither.

The rule is one function, `strutil.ShellSafe`, because it is a security rule and
two copies of one drift.

## Deployment tiers

| Tier | What it contains | What it stops |
|---|---|---|
| **Same user** (default) | One account: daemon, sessions, keys, logs | A remote peer crossing the approval gate. **Not** local code in a session |
| **Separate user** | `tyd up` as `tyd`, sessions as a lower-privileged user | A session reading the daemon's keys, socket or log |
| **Container** | The session inside a container; the daemon outside it | Everything above, including edits to the log from inside the session |

The second and third need setup, and tyd does not do them for you today. What
works today, with no privilege change:

```bash
# The daemon stays as you. The session runs in a rootless container that
# shares your uid, so it can read your files -- and cannot reach the daemon's
# socket, key, or log.
podman run --rm -it --userns=keep-id \
  -v "$HOME/work:/work" \
  registry.fedoraproject.org/fedora-toolbox:41 \
  bash -l
```

Inside that shell, `tyd` finds no socket, no identity and no log: the session is
a container that happens to share your uid, and the daemon's state is outside
it. That is the tier where "I do not trust this session" becomes a statement
rather than a hope.

To go further — sessions as a genuinely different uid — the daemon needs
`CAP_SETUID`, which contradicts the per-user, no-sudo install tyd is built
around. That trade has not been made.

## Reporting

Security issues in tyd: open a private advisory on the repository rather than a
public issue.

A send is bounded and never blocks a takeover. `--session-send-timeout`
(default `5s`, capped at `30s`) stops a send whose PTY will not accept input,
and `attach` preempts a send that is still in progress. Neither path lets a
stalled write hold the attach slot, so a client cannot pin a session by
typing into a program that never reads.
