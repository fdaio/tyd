# tyd

tyd maintains persistent, remotely attachable terminal sessions on a machine.

Step 2 adds Ed25519 identity and session capabilities on the same local Unix socket.

## Build

```bash
make build
```

## Use

```bash
./tyd keygen          # writes ~/.tyd/id_ed25519 and trusted.json
./tyd serve           # trusts only keys in ~/.tyd/trusted.json

id=$(./tyd create)
./tyd list
./tyd attach "$id"    # Ctrl-\ detaches; the shell keeps running
./tyd close "$id"
```

`attach` is not `write`. A key granted only `attach` on a session can watch output but cannot type.

Default socket: `$HOME/.tyd/tyd.sock`. Identity and trust paths can be overridden with `--identity` and `--trust`.

This step does not include TCP, TLS, or switching Unix users.
