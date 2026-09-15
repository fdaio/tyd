# Overview

## One-line definition

> **tyd maintains persistent, remotely attachable terminal sessions on a machine.**

## What it is

tyd is a daemon plus a single CLI binary. On the target machine it:

1. Creates PTY sessions and starts a shell
2. Keeps the shell alive when the client disconnects
3. Lets a client reattach later
4. Authenticates who is connecting (Ed25519)
5. Authorizes what that identity may do on which session
6. Speaks over a local Unix socket and/or TLS TCP

FDA-facing features (file transfer, non-interactive exec, approval workflows, mesh networking) are **out of scope** for tyd. They can sit on top of it.

## Architecture

```text
  tyd CLI (keygen / up / register / accept / status / session …)
           │
           │  Transport: unix  |  tls (TCP+TLS, opt-in)
           │  Frame protocol (length-prefixed JSON)
           │  Ed25519 challenge-response
           ▼
        ┌─────┐
        │ tyd │  up
        └──┬──┘
           │
     Session Manager
           │
        PTY master → PTY slave → /bin/bash (or $SHELL)
```

Control Panel pairing (ids + peer public keys only) is documented in
[requirements/control-plane-pairing.md](requirements/control-plane-pairing.md).

Layers from bottom to top:

| Layer | Responsibility |
|-------|----------------|
| Session / PTY | Create, I/O, resize, signal, close; survive client drop |
| AuthZ | Capabilities: list, create, attach, write, resize, signal, close |
| AuthN | Ed25519 identity; trust file of public keys |
| Protocol | Shared frames over any byte stream |
| Transport | How the stream is obtained: `unix` or `tls` |

Connectivity overlays (WireGuard, NetBird, Tailcat) are **below or beside** Transport. They are not implemented inside tyd today.

## Process model

- One binary: `tyd`
- `tyd serve` holds sessions in memory
- Other subcommands are clients
- Client disconnect or `Ctrl-\` detach does **not** kill the shell
- Daemon restart **does** drop all sessions (no persist yet)

## Security model (completed)

1. **Transport confidentiality (TLS path):** TLS 1.3; client pins server certificate (fingerprint via `--tls-cert`). Plain TCP is not a supported client mode.
2. **Identity:** Every connection must complete Ed25519 challenge-response against `trusted.json`.
3. **Authorization:** Global caps (`list`, `create`) vs session-bound caps (`attach`, `write`, …). Creating a session grants the creator owner caps on that session **in memory** only.

## Explicit non-goals (so far)

- SSH as a dependency or protocol
- Tailcat / NetBird / STUN / custom relay inside tyd
- Unix user switching (UID/GID) for shells
- Durable audit log of terminal contents
- Session restore after daemon restart
- Multiple simultaneous writers on one session
- File transfer, port forward, non-interactive command API
