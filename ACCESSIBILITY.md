# Accessibility

tyd is a command-line tool for persistent terminal sessions. This page states
what accessibility covers, what the CLI and documentation do today, what is
missing, and how to report a barrier.

## Scope

In scope:

- the `tyd` CLI on Linux, macOS, and FreeBSD;
- the documentation in this repository: `README.md`, `docs/`, and
  `CONTRIBUTING.md`.

Out of scope:

- the hosted Control Panel at `app.getfda.dev`. Its web interface is not part
  of this repository. The `controlpanel` binary here serves the registration
  API and the install script, not that interface.
- programs that run inside a tyd session. They are separate programs with
  their own accessibility.

## Target

No formal accessibility audit has been performed. This project does not claim
conformance with WCAG or any other standard.

For documentation, WCAG 2.2 Level AA is the target, within the limits of
GitHub's Markdown rendering. For the CLI, the four WCAG principles are review
criteria where a terminal allows: perceivable, operable, understandable, and
robust.

## What the CLI does

- Every command is keyboard-driven; no mouse is needed.
- Normal output is plain text on stdout or stderr. Color is used only when the
  stream is a terminal, and it never carries meaning alone: state and labels
  are also written as text.
- Output stays stable when piped or redirected: no color, and no in-place
  updates outside a terminal.
- `tyd invite --no-wait` prints the invite and exits, instead of refreshing a
  countdown line. Use it when a changing line is hard to follow.

## Known limitations

- A session is a PTY relay. The shell or full-screen program inside the session
  controls its own accessibility, and tyd does not provide a separate
  accessible view. The terminal emulator and screen reader are also outside
  tyd's control.
- On a terminal, `tyd invite` refreshes the time-to-live line in place.
  `--no-wait` avoids that redraw.
- Color is enabled only when the output stream is a terminal. There is no
  `NO_COLOR` switch today; redirecting a stream removes color from it.
- Listings are plain-text tables. In a narrow terminal, columns can wrap and
  become harder to follow.
- No automated accessibility test runs in CI. Reviews are manual.

## Documentation

The documentation uses Markdown headings, lists, and fenced code blocks. The
only images are the README badges, and each badge has alt text. Essential
information is written as text, not carried by color or position alone.

When you add a diagram, include a text description that carries the same
information.

## Reporting a barrier

Open an issue with the `accessibility` label:

https://github.com/fdaio/tyd/issues/new?labels=accessibility

Include:

- what you were trying to do;
- the command and its output;
- your operating system, terminal emulator, and assistive technology;
- what you expected and what happened instead.

Remove tokens, keys, hostnames, and session content before posting. If the
report needs details you do not want public, open the issue without those
details and ask a maintainer for a private channel.

## Contributing

When you change the CLI:

- keep output plain and parseable;
- do not convey state, errors, or required actions by color alone;
- avoid cursor movement and in-place redraws outside a terminal;
- check the result on a terminal and with stdout piped;
- describe the accessibility effect in the pull request when the output
  changes.

When you change documentation:

- use real headings in order;
- give images alt text and links descriptive text;
- add a text description for diagrams;
- keep code blocks fenced and labelled with a language.

There is no automated accessibility check yet. State any manual check you ran
in the pull request.

## Review

This page is reviewed when the CLI output or the documentation structure
changes.

Last reviewed: 2026-10-22.
