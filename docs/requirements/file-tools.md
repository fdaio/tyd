# `tyd mcp`: file read and write

Goal: a model can read and write a file without shelling out, without the
content passing through the terminal, and without an operator approving
something other than what they were shown.

Status: **design under review. Nothing implemented.** Three implementation PRs,
none opened yet. See "Review" at the end for what is still owed.

## 1. The threat model, stated so it is not misread

**The root is not a sandbox.** A model with `session_send` has a shell, and the
shell reaches anywhere the daemon's user reaches. It can `ln` a hard link,
`cat` anything, or `cd` out of any directory. Nothing here stops that, and no
document should imply otherwise.

So the root restriction is **not** a privilege boundary. It restricts the *file
tools*, and it protects exactly one thing:

> **Approval integrity.** The operator approved "write `foo/bar.txt`, 1 KB". When
> the write happens, it must be that file — not wherever a symlink someone
> swapped in between the check and the use now points.

That is the whole promise, and it is a promise about *this operation*, not about
the model's reach. It is also the correct reason hard links may be allowed: a
hard link inside the root to a file outside it does not cross a privilege
boundary, because the same user could read that file directly anyway.

## 2. Why not just use the shell

- `cat`'s output goes through the escape cleaner and a page truncation, so byte
  counts stop meaning anything.
- Reading one file over the shell is **two** gated requests on a `pre` target: a
  `send` and a `read`. A file read is one.
- Written content lands in the terminal's scrollback and in the session's output
  log, where it cannot be redacted afterwards — an echoed byte and ordinary
  program output are indistinguishable.

Writing is a different risk shape from typing: it is not reversible, and it can
become code execution (`.git/hooks/*`, shell startup files,
`~/.ssh/authorized_keys`, cron). So the default posture is **fail-closed**: no
configured root, no file tools.

## 3. The root: configured by an operator, never by the model

`--file-root` is a ceiling, set by the operator of the machine where the agent
runs. `session_open {root}` may narrow it. It may never widen it.

- **No `--file-root` means the file tools do not exist**, whatever the caller
  passes. `root` is not a way to obtain them.
- **`/` is refused, with no switch.** Any use that genuinely needs the whole
  filesystem wants a narrower root, and a switch that permits `/` would be a
  switch that disables the feature's only guarantee.
- **`$HOME` is refused unless `--file-root-allow-home` is given**, which logs a
  loud line at startup. `$HOME` is a real default for a shell-based tool and an
  unreasonable root for a file API, so it is available and never silent.
- **The agent re-validates.** A `root` arriving from a daemon is a claim, not a
  fact. This is the #118 lesson: a field forwarded across two hops is checked
  where the resource is, and the test asserts the field *arrived* — it does not
  let the agent trust that the far end already checked it.

### 3.1 The root defaults to `$HOME`, which is why this needs saying

A session's shell starts in `CreateOpts.Cwd`, or `$HOME` when that is empty —
and `tyd mcp` never passes a cwd. So today **every** MCP session's initial cwd is
`$HOME`, which §3 refuses.

This is why the root cannot be "the session's initial cwd". It would make the
feature unavailable in the common case, and even when permitted it would be
wrong: the shell `cd`s into a project and the file tools would still be pinned to
`$HOME`, which is not where the model is working.

The root is taken **once**, at session open, as an open directory descriptor.
Not a path string — a path can be re-pointed. Not the shell's current directory —
`cd` must not move it.

## 4. Path resolution: `os.Root`

The manual version of this was going to be `openat2(RESOLVE_BENEATH |
RESOLVE_NO_SYMLINKS)` on Linux and a per-component `openat` walk elsewhere, with
symlinks refused outright. **Go's `os.Root` already is that**, and
`go.mod` requires 1.26, well past the 1.24 that introduced it. It has `OpenFile`,
`Lstat`, `Stat`, `ReadFile`, `WriteFile`, `Create`, `Rename`, `Chmod`, `Chown` —
everything this design needs — and it is safe for concurrent use, which matters
because the agent serves requests in parallel.

So the most security-sensitive layer in the design is the standard library's, and a
reviewer is asked to check how this design *uses* it rather than whether a
hand-rolled walk is correct. That is a much better thing to spend a review on.

What `os.Root` guarantees, in its own words: methods only access locations beneath
the root; if any component of a name references a location outside it, the method
errors; symbolic links must not be absolute.

### 4.1 What it does not do, and what that costs

**`os.Root` follows symlinks that stay inside the root — including one in the
final component, and a caller's own `O_NOFOLLOW` does not stop it.** The earlier
draft refused any symlink at all. So the final component is refused here, but it
takes one step that `os.Root` does not.

The reason is worth writing down, because it is the kind of thing that reads as
obvious and is not. `os.Root` always passes `O_NOFOLLOW` down, and when the kernel
refuses, its `doInRoot` treats the result as `errSymlink` and **resolves the link
itself** — the comment in the standard library says so: *"If f returns errSymlink,
this element is a symlink which should be followed."* Verified against the toolchain
in use: `os.Root.OpenFile("link")` on a symlink returns a readable file, not an
error.

So the walk stays with `os.Root` and only the **last step is taken directly**: the
parent directory is opened through `os.Root` — which confines every intermediate
component, including a symlinked one — and the final component is then opened with
`openat(parentfd, base, O_NOFOLLOW | O_NONBLOCK)`. The kernel refuses the link as
part of the open, with no window between a check and a use.

`O_NONBLOCK` is in that call for a second reason: without it, opening a FIFO for
reading waits for a writer that may never arrive, and a "not a regular file" answer
becomes a hang instead of a result.

A symlinked intermediate *directory* is still followed, since `os.Root` allows it as
long as it stays inside the root.

For a write, the target is examined with **`Lstat`, not `Stat`** — `Stat` would
resolve a link and report its target, so a write to `link` would be approved as a
write to whatever it points at, and a write to a *dangling* link would look like a
create. A symlinked target is then refused rather than replaced. The
temp-file-then-rename in §6 would not follow it either, since it swaps the entry, so
nothing would escape; but silently destroying a link that somebody put there is not
what "write to this path" means.

The approval promise therefore weakens, and §1 has to say so honestly:

- Before: the operator approved `foo/bar.txt`, and `foo/bar.txt` changed.
- Now: the operator approved `foo/bar.txt`, and that path — resolved within the
  root at the time of the call, with a symlinked final component refused — changed.

The residual is a symlinked directory *inside* the root redirecting an approved
write to another file *inside* the root. Under §1's model that crosses no privilege
boundary: it is the same user, inside their own root, and the same user could have
made the edit. What cannot happen is a write landing outside the root, and that is
unconditional.

**Accepted, as the default position.** The residual stays inside the root and
crosses no privilege boundary, while the alternative is a hand-rolled walk somebody
has to review line by line. Refusing every symlink remains available at that cost;
recording it as a decision rather than an open question means overturning it is a
deliberate act rather than a drift.

**`Root.Chmod`, `Root.Chown` and `Root.Chtimes` are documented as racy on Unix** —
the target can be changed from a regular file to a symlink mid-operation. So §6
never uses them: permissions and ownership are set on the **temporary file's own
descriptor**, which cannot be swapped out from under us. That is both correct and
one fewer thing to get wrong.

### 4.2 File types

- Read: `Root.OpenFile` with `O_NONBLOCK`, then `fstat` on the returned file and
  require a regular one. Without `O_NONBLOCK` a FIFO blocks the open forever, and a
  device node is worse. `Root.OpenFile` passes flags through, so this is unchanged.
- Write: the target is a regular file (replace) or does not exist (create).

### 4.3 Known limits, documented rather than papered over

- **Hard links**: a link inside the root can point outside it. A read then
  returns outside content. A write replaces the link, not the target, so it does
  not modify the outside file. Not refused by default — see §1 for why that is
  correct, and why refusing would break git objects.
- Another process owned by the same user can change things inside the root
  concurrently. Nothing here defends against that.

### 4.4 Sensitive paths: defence in depth, not a boundary

Refused **lexically, by name, before opening anything**. That ordering matters:
deciding after an open would make "refused because it is sensitive" different from
"refused because it is missing", and that difference leaks whether a path exists.

- Writes refuse: `.git/hooks/`, `.ssh/`, `.gnupg/`, and common shell startup
  files. These are the paths that turn a write into code execution.
- Reads refuse: `.ssh/` private keys, `.gnupg/`, `.aws/credentials`. Exact names
  rather than globs — a `.env*` glob hits `.env.example` and trains people to
  disable the check.

The list is configurable. In v1 it is on by default with no off switch.

## 5. Approval: one request, bound to this operation

Both operations are **one** gated request each, so a `pre` target's single
approval covers one file operation — against two for the shell equivalent.

**The rule: bind exactly what the operator can see.** No more, no less. Operation,
path or session, byte count, mode.

`expected_sha256` is **not** in the digest — it is absent from the formula above on
purpose — and appears **nowhere** the operator can read it. It is a hash the writing side claims about existing content, which on a
low-entropy file is the same offline dictionary verifier as a bare hash in the audit
log. It is the writer's concurrency guard, not part of what is being approved.

**Known limit, stated rather than implied.** For a `send` the digest carries a byte
count, so a different payload of the same length still matches. What this fixes is
one request spending another's approval — a read spending an approval granted for
keystrokes, an approved path swapped for another. It is **not** content binding.
Content binding would need an HMAC under a daemon-private key, which would bind
something the operator cannot see and therefore could not meaningfully have
approved.

**This is a change to the existing gate, and it is not optional.** Today
`consumeApproval` is keyed by `gateKey(sessionID, principal)` and its value is a
bare expiry: the approval is bound to *this session from this principal*, not to
*this request*. The operator is told:

```
tyd approval needed: <principal> wants session <id> (tyd session approve <id>)
```

— which does not say whether this is a read or a write, let alone which file.
Inside the 10-minute window, whoever calls first spends it.

That is survivable while every gated request is a read or a keystroke against a
session the operator already named. It is not survivable once a write to
`~/.ssh/authorized_keys` can spend an approval granted for a `cat`.

So a file request carries a digest of what it intends to do:

```
digest = SHA-256( op \0 session \0 relpath \0 size \0 mode )
```

- `approved` holds `{expires, digest}` instead of a bare expiry.
- `consumeApproval` spends only on a digest match. A mismatch is a refusal, and
  the approval stays where it was.
- The pending record carries the digest and the operation summary, and
  `tyd session approve <id>` **prints what it is approving** — operation, relative
  path, byte count, create or replace — before it takes effect.

The key becomes `(session, principal, digest)`, so two different operations on one
session need two approvals rather than racing for one.

**`size` is the request, not the result.** For a write it is the content's length,
which the daemon knows before it sends anything. For a read there is no content, and
the number that is both known in advance and meaningful to an operator is the
requested `max_bytes` — so that is what goes in. The page the agent returns is the
agent's decision and is deliberately **not** in the digest: binding it would mean the
daemon had to predict the file's size before reading it, and a digest nobody can
compute in advance is not something an operator can meaningfully approve.

**The digest must name the path, and today's does not.** `approvalDigest` is
currently `(op, session, size)`, which is enough for `send` and `attach` because a
session id already names the thing being acted on. A file request breaks that
assumption: with no path in the digest, an approval granted for reading `notes.txt`
would be spent by a read of `authorized_keys`, which is the exact hole this section
exists to close. So B2 extends the digest rather than reusing it as it stands.

**The approval is spent before the operation runs, and a failed operation keeps it
spent.** `gateAttach` spends first and performs second; with no matching approval the
operation does not happen at all and the caller is told to get one. The alternative —
perform, then refund on failure — turns "approved once" into "one approval per
successful read", which is a discovery oracle: it would let a caller walk a
filesystem, spending nothing on every path that is not there. So a file operation
refused for a missing file, a symlink or a bad parameter has still consumed the
operator's approval. That is the intended behaviour, recorded here so it is not later
smoothed over as an inconvenience.

## 6. Write semantics

1. Create a temporary file in the target's own directory, via the descriptor:
   `O_EXCL | O_CREAT`, mode `0600`.
2. Write, then `fsync` the file.
3. `fchmod` to the target's existing permissions (replace) or the default
   (create). `fchown` back to the target's owner where permitted; failure is not
   fatal.
4. `renameat` onto the target, then `fsync` the directory.
5. Any failure removes the temporary file and leaves the original untouched.

`internal/safefile.WriteFile` already does temp + `fsync` + `rename` + `syncDir`
and is a good model to copy — but it works **by path**, so it does not satisfy
§4. It needs a descriptor-based sibling, not a reuse.

Not preserved, and said so in the tool description: ACLs, xattrs, hard-link
relationships.

**Residual window**: the `expected_sha256` comparison and the rename are not
atomic. `flock` narrows it for cooperating processes only. This is best-effort
and documented as such.

**A size ceiling the transport imposes underneath the library's.** The library caps a
write at 1 MiB. The content travels in the JSON frame as base64, and a frame is
capped at 1 MiB, so base64's four-thirds expansion means a write anywhere near the
library's ceiling is rejected by the frame layer before the agent ever sees it — as
an opaque "frame too large" rather than as `too_large`. The agent's own check
therefore cannot be the one that fires at the top of the range.

So the effective ceiling is the smaller of the two, and **B2 enforces it before
sending**, where it can be reported as `too_large` with a number in it. Roughly
700 KiB of content is the practical limit. This is recorded here rather than left
for B2 to discover, because it is arithmetic rather than judgement.

Sizes: read defaults to 64 KiB and caps at 1 MiB; write caps at 1 MiB.

## 7. Audit

Recorded: time, peer, session, operation, **root-relative path**, byte count,
result.

**Never recorded: content.** Not on success, not on failure. This matches #122:
input content never enters the audit; a byte count may.

`audit.Event` has no content field today, so that is structural rather than a
promise. It does have `Bytes`.

**On the hash.** An earlier suggestion here was to record a bare sha256 of the
content. That is wrong: for low-entropy content — a short password, a token — a
bare hash is an offline dictionary-attack verifier, and anyone holding the log can
confirm a guess. So:

- **HMAC-SHA256 keyed by a separate audit key**, held by the daemon in its own
  `0600` file and never written to the log. Whoever holds the log cannot verify a
  guess offline; the daemon can still do an integrity comparison.
- Cost: after a key rotation, older records cannot be compared. Recorded, and
  accepted.

The key is **created by writing it and linking it into place**, not by creating the
name and then writing into it. `O_EXCL` publishes the name first, so a second daemon
starting in that window reads a zero-length file and reports a corrupt key rather
than the race it is; `link(2)` is atomic and fails when the name is taken, so
exactly one creator wins and its content is complete before the name is visible. A
`rename` would not do — it overwrites, so two daemons would each replace the other's
key and be unable to verify each other's records.

The key is **not** optional at runtime in the sense of falling back: an unreadable
key, or one whose mode is wider than `0600`, **stops startup**. Continuing would
produce records that carry a MAC and mean nothing.

## 8. Errors

Distinguished, because the fix differs:

| code | meaning |
|---|---|
| `outside_root` | the path resolved above the root |
| `blocked_path` | refused by the sensitive-path list, decided by name |
| `not_found` | no such file |
| `exists` | `create` and the file is already there |
| `not_regular` | a directory, FIFO or device |
| `too_large` | over a cap |
| `conflict` | `expected_sha256` did not match |
| `unavailable` | no root configured, or none valid |
| `symlink` | the final component is a symlink |
| `denied` | the daemon's own user cannot read or write it |

The last two were added while implementing §4.1, because the table as first written
had no name for two outcomes the code can actually produce. `symlink` cannot be
folded into `not_regular` — it resolves to a regular file — or into `blocked_path`,
which means the sensitive-path list. `denied` is separated for the same reason the
others are: an operator fixes it with a `chmod`, and reporting it as anything else
sends them looking in the wrong place.

Paths in errors are root-relative. An absolute path outside the root is never
echoed back.

## 9. Tools

```
file_read  { session | peer, path, offset?, max_bytes? }
           -> { bytes_b64, size, truncated, mtime }
file_write { session | peer, path, content_b64,
             mode: "create" | "replace", expected_sha256? }
           -> { bytes_written, created, sha256 }
```

Content is base64 in both directions; text-versus-binary is not guessed.

`--read-only`: `file_write` is **not registered** and calling it is
`unknownTool`. That is already what happens to `session_send`,
`session_interrupt` and `session_close`, so there is nothing new to decide.

The approval prompt shows operation, relative path, byte count and
create-or-replace. **Not** the content — and content shown would be content in a
place that is not the audit log.

## 10. Where the work happens

The PTY is held by the **live agent**, so the directory descriptor has to be
too: the daemon never touches the session's filesystem. File operations are
therefore two new dataplane RPCs, and for a remote peer they cross two hops.

Consequences that are easy to get wrong:

- A field that must reach the agent is **forwarded, not interpreted**, at both
  hops — and the test asserts it arrived. #118's `secret` flag was nearly
  fail-open for exactly this reason.
- The agent validates the root and the path itself. Trusting the daemon's check
  would make the check a policy decision on a machine that has no say in it.

## 11. Implementation, as three PRs

Each merges with the feature still off.

**A — the library, unwired.** Descriptor-relative resolution and the
descriptor-based atomic write in the agent. No protocol, no tools. This is the
security-critical part and the one worth reviewing on its own: symlink-swap races
under `-race`, FIFO and device files, failure injection before the rename, and a
root that has been deleted or renamed.

**B — the two RPCs**, split in two, each merging with the feature still off.

- **B1 — the agent.** The RPC handling, the `--file-root` ceiling re-validated in
  the agent, parameter validation, the audit fields, and the HMAC key in its own
  `0600` file. One hop, tested against the agent on its own: no second process, no
  forwarding, so a failure here is the agent's and nothing else's.
- **B2 — the forwarding.** Server to peer to agent, with the tests that assert each
  field **arrived** at the agent rather than merely being sent. The digest is still
  computed by the daemon from the request it is serving, and a digest that arrives
  from a peer is not believed — that is the #132 position, and B2 is where it has to
  hold.

The reason for the split is that B2's tests are the expensive ones: each needs a
full server fixture at about 0.12s a run. Keeping them in their own PR keeps the
agent's own tests cheap enough to iterate on, and keeps a failure in a forwarding
test unambiguously a forwarding bug.

**C — the tools.** `file_read`, `file_write`, `session_open {root}`,
`--file-root`, the schema snapshot and contract test, and the documentation.

## 12. Tests

`os.Root` is documented as safe for concurrent use, and the agent serves requests
in parallel, so nothing here adds a lock around a `*os.Root`. The tests assume that
and would catch it if it stopped being true.


**Paths** — `..`, absolute, NUL, over-long; a symlinked parent directory pointing
outside is refused; a concurrent goroutine swapping a directory component for a
symlink throughout the operation never escapes the root under `-race`; a symlinked
**final** component gives `symlink` — for a read from the `openat` in §4.1, for a
write from the `Lstat` — while a symlinked intermediate directory redirects
**within** the root, which §4.1 concedes and the test pins so the concession cannot
change silently; FIFO, device and directory give `not_regular` rather than blocking;
a denial is `denied` and not one of the other codes; root renamed or deleted has
defined behaviour, because the root is a descriptor.

The refusal of a final symlink is asserted **against `os.Root`'s actual behaviour**
as well as against this package's, so the difference §4.1 describes cannot quietly
disappear in a Go release.

**Writes** — a target that is a symbolic link is refused with `symlink`, including a
dangling one, and is never written through; failure injected
before the rename leaves the original untouched and removes the temporary file; a crash point leaves no half-written target; `create`
on an existing file and `replace` on a missing one both fail; a mismatched
`expected_sha256` is refused; permissions and ownership survive.

**Approval** — one read and one write on a `pre` target each trigger exactly one
approval; an approval granted for one operation is **not** spent by a different
one, which is the test that §5 exists for; `--read-only` leaves no way to write.

**Logging** — write content containing a canary, then search the audit log, the
output log and every error string for it; it must appear nowhere. The HMAC matches
for identical content and differs after a key rotation.

## 13. Not in v1

Directory listing or traversal. Delete, rename, chmod. Streaming large files.
Wildcard allowlists outside the root.

## Review

**Before PR A:** a reader who is neither the author nor the owner who reviewed
#118. The brief for them is
[`file-tools-review-brief.md`](file-tools-review-brief.md) — one PR, a few hundred
lines, and a checklist. Naming that person is outside this repository.

**Decided:** §4.1's concession is accepted, and the approval rule of §5 is settled.
What remains is the reader for PR A, which this repository cannot name, and the
operator-facing documentation that stands in its place — the operator has to be able
to see exactly what they approved.
