# 2c: bound send; a human can always take over

Goal: no send can wedge a session or block an attach, and two small defects
get closed.

## Mechanism (settled by measurement)

A PTY master's `SetWriteDeadline` returns `file type does not support
deadline` on this platform, so a write deadline cannot bound the write
directly. The fallback applies: **one writer goroutine per session with a
bounded queue (64KB)**. A send replies once the writer has finished, and an
attach drops the queue. The PTY write goes through an indirection so a test
can substitute a writer that blocks forever, because Linux and macOS both
absorb the input and the real block is not reproducible.

## Invariants

1. `attach`, `watch`, `read`, `close`, `resize` and `signal` never wait on a
   send's PTY write.
2. Server-side send timeout: default 5s, configurable, capped at 30s. When it
   fires the write is really aborted, not left running. The reply is error
   `send timed out` with the exact `written` count. No byte past `written` is
   ever written later, so retrying the remainder is safe.
3. Attach preempts. An attach that claims the slot aborts an in-flight send
   with `preempted` and its `written` count. After the attach is granted no
   further send bytes reach the PTY, except a partial write already counted
   in `written`. A send arriving while someone is attached still gets
   `session in use`.
4. Sends are serialised per session. A second concurrent send is rejected
   immediately with `session busy: a send is in progress` (retryable), so
   bytes never interleave and sends do not queue.
5. Send data is written in chunks (1KB), so timeout and preempt are checked
   between chunks.

## Also in this PR

- **Fingerprint test.** `TestDialTLSFingerprintRejectsMismatch` built its
  "mismatched" fingerprint as `"00"+fp[2:]`, which is *identical* to the real
  one whenever the real one starts with `00` (1/256). The dial then correctly
  succeeded and the test failed. That is a real defect in a security test,
  not a flake. Other tests that derive a fake value from a real one are
  checked for the same mistake.
- **Socket path validation.** The live-agent socket path is subject to the
  `AF_UNIX` limit of about 104 bytes. A long `HOME` makes the agent fail to
  start with `connect: invalid argument` and no actionable message. `tyd up`
  and `session create` fail early, and `tyd doctor` reports it. A short
  fallback socket directory is out of scope.

## Out of scope

MCP, leases, terminal content in audit, changing `read`.
