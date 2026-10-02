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

**`os.Root` follows symlinks that stay inside the root.** The earlier draft refused
any symlink at all. Under this design that becomes: the final component is checked
with `Lstat` and refused if it is a symlink, while a symlinked intermediate
*directory* is still followed.

The approval promise therefore weakens, and §1 has to say so honestly:

- Before: the operator approved `foo/bar.txt`, and `foo/bar.txt` changed.
- Now: the operator approved `foo/bar.txt`, and that path — resolved within the
  root at the time of the call, with a symlinked final component refused — changed.

The residual is a symlinked directory *inside* the root redirecting an approved
write to another file *inside* the root. Under §1's model that crosses no privilege
boundary: it is the same user, inside their own root, and the same user could have
made the edit. What cannot happen is a write landing outside the root, and that is
unconditional.

Refusing every symlink is still available, at the cost of writing the walk by hand
and reviewing it. That is a real choice and a reviewer should be told it exists.

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
digest = SHA-256( op \0 relpath \0 size \0 mode \0 expected_sha256 )
```

- `approved` holds `{expires, digest}` instead of a bare expiry.
- `consumeApproval` spends only on a digest match. A mismatch is a refusal, and
  the approval stays where it was.
- The pending record carries the digest and the operation summary, and
  `tyd session approve <id>` **prints what it is approving** — operation, relative
  path, byte count, create or replace — before it takes effect.

The key becomes `(session, principal, digest)`, so two different operations on one
session need two approvals rather than racing for one.

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

**B — the two RPCs.** Both hops, the field-arrives-at-the-agent tests, the
agent-side ceiling check, the audit fields and the HMAC key in its own `0600`
file.

**C — the tools.** `file_read`, `file_write`, `session_open {root}`,
`--file-root`, the schema snapshot and contract test, and the documentation.

## 12. Tests

`os.Root` is documented as safe for concurrent use, and the agent serves requests
in parallel, so nothing here adds a lock around a `*os.Root`. The tests assume that
and would catch it if it stopped being true.


**Paths** — `..`, absolute, NUL, over-long; a symlinked parent directory pointing
outside is refused; a concurrent goroutine swapping a directory component for a
symlink throughout the operation never escapes the root under `-race`; a symlinked
**final** component is refused by the `Lstat` check, while a symlinked intermediate
directory redirects **within** the root — §4.1 concedes that, and the test pins it
so the concession cannot change silently; FIFO, device and directory give
`not_regular` rather than blocking; root deleted or renamed has defined
behaviour.

**Writes** — failure injected before the rename leaves the original untouched and
removes the temporary file; a crash point leaves no half-written target; `create`
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

**Not yet decided:** whether §4.1's concession (a symlinked intermediate directory
may redirect within the root) is acceptable. That is the one choice in this design
that decides whether PR A is a thin layer over the standard library or a
hand-rolled walk someone has to review line by line.
