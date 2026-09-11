# tyd

tyd maintains persistent, remotely attachable terminal sessions on a machine.

Step 3 adds a Transport layer: local Unix socket and TLS TCP (default `127.0.0.1:61211`), plus connection topology via `tyd status`.

## Build

```bash
make build
```

## Use

```bash
./tyd keygen
./tyd serve                 # unix + TLS on 127.0.0.1:61211
# ./tyd serve --listen off  # unix only

id=$(./tyd create)
./tyd status
./tyd attach "$id"
./tyd close "$id"

# TLS client (pin server cert)
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt create
./tyd --addr 127.0.0.1:61211 --tls-cert ~/.tyd/server.crt status
```

`attach` is not `write`. Topology shows transport, addresses, TLS fingerprint, principal, and session.

This step does not include Tailcat/NetBird, SSH, or switching Unix users.
