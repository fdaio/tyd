# Reviewer brief: file tools, PR A

For a reader deciding whether to take this on. One PR, no protocol, no tools, no
wiring — a thin layer over `os.Root` plus the things `os.Root` does not do.

## What you would be looking at

A library in the agent process that, given a root directory, opens and reads a
file, and writes one atomically, refusing anything above the root and anything on
a deny list. It is not reachable from `tyd mcp` yet and cannot be, by design: the
tools and the protocol arrive in later PRs.

Roughly a few hundred lines, most of it tests.

## Why you, and not someone else

- **The work is fd-relative path handling**, which is a small subject with a long
  history of being got wrong.
- **Nothing here is a novel security primitive.** The escape-proof part is Go's
  `os.Root`. The review is whether this design uses it correctly and whether the
  parts it delegates are the right parts — not whether a hand-rolled walk is sound.
- **You are neither the author nor the owner** who reviewed #118. That matters:
  #118's review was its author reviewing their own work, which is weaker than it
  looks, and this code sits on top of it.

Not required: prior familiarity with tyd. The design document is
[`file-tools.md`](file-tools.md) and it is meant to be read first.

## Order to read it in

1. `file-tools.md` §1 — the threat model. **This is the part to disagree with
   first.** Everything else follows from it, and it is the easiest thing to get
   wrong in a way that looks fine.
2. `file-tools.md` §4 — what `os.Root` does and does not do, and what §4.1 concedes.
3. The code, with this checklist.

## Checklist

**The threat model (§1), before the code**

- Does "the root is not a sandbox, it protects approval integrity" actually hold
  for the code as written, or has something crept in that assumes containment?
- §4.1 concedes that a symlinked intermediate directory can redirect an approved
  write to another file **inside** the root. Is that concession right, or is it the
  line? If it is the line, the hand-rolled walk is back and that is a bigger PR.

**Path resolution**

- `..`, absolute paths, NUL bytes, over-long paths. What does each return?
- A path escaping the root by every route you can think of: `..` mid-path, an
  absolute symlink, a symlink chain, a symlinked parent. `os.Root` should refuse
  all of them — check that the code relies on that rather than re-deriving it.
- **A symlinked final component** is refused via `Lstat`. Is that check ordered so
  it cannot be raced? What happens on a platform where `Lstat` and the subsequent
  open differ?
- A root that is deleted or renamed while a call is in flight. `os.Root` holds a
  descriptor, so this should keep working — confirm it does, and that the code
  does not cache a path anywhere.

**File types**

- A FIFO must give `not_regular` rather than blocking. The flag is `O_NONBLOCK` and
  then `fstat`; check the order, because `fstat` after a blocking open is too late.
- Device nodes and directories: refused, not read.
- The same for the write path: a target that is a directory, a FIFO or a device.

**Writes**

- The temp file is created `O_EXCL` in the target's own directory through the root.
  **Every failure between creation and rename must remove it** and leave the
  original untouched — walk the error paths, not the happy one.
- Permissions and ownership are set on the **temp file's descriptor**, never through
  a path. `Root.Chmod`/`Chown`/`Chtimes` are documented as racy on Unix; confirm
  nothing goes through them.
- `fsync` before rename, and the directory `fsync` after. Is the first one before
  the rename in every path?
- `create` on an existing file, and `replace` on a missing one: both refuse.
- `expected_sha256` mismatched: refuses, and the original is untouched.
- Is the rename itself the last thing, with nothing between the write and it?

**The deny list**

- Decided **lexically, by name, before anything is opened**. This is deliberate:
  deciding after an open would make "refused because sensitive" differ from
  "refused because missing", and that difference leaks whether a path exists.
- Is any entry matched in a way that could be bypassed — case, `..` mixed into a
  name, a trailing separator, a Unicode lookalike?

**Limits and errors**

- The read and write caps cannot be exceeded by a lie in the arguments.
- Error strings carry root-relative paths only. An absolute path outside the root
  never appears in an error.
- Is every error in §8's vocabulary reachable, and is any error missing from it?

## What is explicitly not in scope

Directory listing, delete, rename as an operation, chmod, streaming large files,
and anything about the protocol or the tools. If you find yourself wanting to
review those, that is a sign the scope needs discussing rather than expanding here.

## What a result looks like

Anything you are unsure about, named as such, is worth more than a clean approval.
The useful outputs are: "this is wrong and here is a path that does it", "this
concession in §4.1 is the wrong one", and "here is a case the tests do not cover".

Approving without comment is a weak signal for a library whose whole purpose is to
be boring at the boundary.
