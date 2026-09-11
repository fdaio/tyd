# tyd

tyd maintains persistent, remotely attachable terminal sessions on a machine.

Step 1 is local only: one `tyd` binary, a Unix socket, and PTY sessions that survive client disconnect.

## Build

```bash
make build
```

## Use

```bash
# terminal 1
./tyd serve

# terminal 2
id=$(./tyd create)
./tyd list
./tyd attach "$id"
# Ctrl-\ detaches; the shell keeps running
./tyd attach "$id"
./tyd close "$id"
```

Default socket: `$HOME/.tyd/tyd.sock`. Override with `--socket PATH`.

This step does not include TCP, TLS, authentication, or switching Unix users.
