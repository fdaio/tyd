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
input, terminal output and process environment are deliberately never written —
a log that recorded them would be a copy of your session on disk.

In `post` mode the log covers control events only. **It does not record what ran
in the session.** Nothing in tyd records that, by design.

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
