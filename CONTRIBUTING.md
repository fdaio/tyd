# Contributing to tyd

tyd is a Go daemon and CLI that keeps terminal sessions alive across
disconnects. Bug reports, documentation fixes, and focused code changes are
welcome. This file covers local setup, tests, and the pull request process.
For what tyd is and what it deliberately does not do, read
[README.md](README.md) and [docs/overview.md](docs/overview.md).

## Before you start

- Report a reproducible bug with the
  [bug report form](https://github.com/fdaio/tyd/issues/new?template=bug_report.yml).
  Include the `tyd version` output, the operating system and architecture, the
  command you ran, and what happened instead.
- Propose a larger change with the
  [feature request form](https://github.com/fdaio/tyd/issues/new?template=feature_request.yml)
  before you write code. This matters for the wire protocol, pairing, approval,
  the CLI surface, or a change across several packages; agreeing on scope first
  saves a rewrite.
- Do not open a public issue for a security problem. See
  [Security reports](#security-reports) instead.

Small fixes do not need an issue. A typo, a broken link, or a test for an
existing behaviour can go straight to a pull request.

## Requirements

- Go 1.26 or newer. The module declares `go 1.26.0`.
- `git`, a POSIX shell, and `python3` for the acceptance script.
- Linux or macOS for the full local loop. Release builds also cover FreeBSD on
  amd64 and arm64. Windows is not supported.

The unit tests do not need a running daemon. The acceptance script starts one
in a temporary `HOME`, so it does not touch `~/.tyd`.

## Build and test

```bash
git clone git@github.com:fdaio/tyd.git
cd tyd
make test          # unit tests, plus checks of the install and release scripts
go vet ./...       # what CI runs before the tests
make build         # ./tyd
make acceptance    # end-to-end send/read against a real daemon
```

`make test` compiles the packages, so it also catches build errors. Run it
before every commit. CI runs `go vet ./...`, `go test ./...`,
`make acceptance`, and a build on Linux and macOS; a change that passes
locally but fails one of those is not ready.

`make acceptance` needs `python3` and `/bin/bash`. It uses a temporary home
directory and a separate port, so it can run next to a daemon you already use.
It is slower than the unit tests; run it when you touch session I/O, transport,
or the CLI.

`make install` copies the binary to `~/.local/bin` and starts a per-user
daemon. Use `make build` and `./tyd` while developing unless you intend to
replace the daemon on the machine.

## Code

- Run `make fmt` before committing. CI does not run a formatter, so `gofmt`
  output is the baseline for review.
- Prefer the standard library. Open an issue before adding a module dependency.
- Put tests in the package they cover. Use table-driven tests when a function
  has several inputs.
- Comments should explain why: a constraint, an invariant, or a non-obvious
  behaviour. Do not restate what the code already says.
- A change to user-visible behaviour needs a documentation update in `docs/`
  and, when the install or the CLI surface changes, in `README.md`.
- A change to the frame protocol or the handshake needs an update to
  [docs/protocol.md](docs/protocol.md), including the handshake version when the
  change is incompatible.

## Commits

Use a short `area: summary` subject, for example `session: ...` or `docs: ...`.
Say what changed and why in the body, and wrap lines at 72 columns. Keep one
logical change per commit. Do not mix formatting or refactoring with a
behaviour change.

Do not add `Generated with ...` or similar attribution to commits, pull
requests, or code.

## Pull requests

Work on a branch, not on `main`:

```bash
git switch -c fix/short-description
```

Push the branch to your fork, or to this repository if you have write access,
and open a pull request against `main`.

In the description, state:

- what observable behaviour changes and why;
- how you verified it: the commands you ran and their result;
- anything you did not test, or a known limitation.

Keep the diff focused. Do not reformat files you did not change, and do not
include generated binaries, local paths, credentials, or production data. One
logical change per pull request; split unrelated work.

Draft pull requests are fine for early feedback. Mark one ready when the tests
above pass.

## Review and merge

CI must pass. A maintainer reviews for correctness, security, and fit with the
existing design. The merge is a squash, so do not spend effort squashing
locally; keep the branch current by rebasing on `main`.

After review starts, push new commits instead of force-pushing. It keeps the
conversation readable. A maintainer merges; contributors do not need write
access to `main`.

## Releases

The daily `Release` workflow cuts a prerelease, and a manual step promotes it.
See [docs/operations.md](docs/operations.md#daily-release) for the schedule and
the promotion gate. Contributors do not need to run either.

## Security reports

Do not open a public issue for a vulnerability. Report it to the maintainers
privately. [docs/security.md](docs/security.md) describes the boundaries a
report should assume. Include the `tyd version` output, the platform, a
reproduction, and the impact you believe it has.

## AI-assisted contributions

AI-assisted changes are welcome. You are responsible for the result:
understand every line, run the tests, and be able to explain the change in
review. The rules above apply the same way.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

tyd is licensed under Apache-2.0. Contributions are accepted under the same
terms; no separate CLA is required.
