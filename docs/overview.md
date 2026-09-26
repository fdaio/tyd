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
6. Speaks over a local Unix socket, optional TLS TCP, a QUIC peer data plane, and a relay fallback

File transfer, non-interactive exec, approval workflows, and mesh networking are **out of
scope** for tyd. They can sit on top of it.

## Architecture

```text
  tyd CLI (up / register / invite / accept / peer / status / session / alias / doctor …)
            │
            │  Transport: unix | tls (opt-in) | quic (peer DP) | relay (fallback)
            │  Frame protocol (length-prefixed JSON)
            │  Ed25519 challenge-response
            ▼
         ┌─────┐         WebSocket rendezvous (default CP /relay;
         │ tyd │  up  ───▶  optional standalone tyd-relay; blind splice)
         └──┬──┘
            │  re-adopts surviving agents on start
            ▼
      live-agent (one process per session, under ~/.tyd/live/<id>/)
            │
         PTY master → PTY slave → $SHELL (or /bin/bash, /bin/zsh, /bin/sh)
```

Each session runs in its own **live-agent** process, so the PTY outlives the daemon.
A graceful `tyd up` stop (SIGINT/SIGTERM) detaches clients and leaves the agents
running; the next `tyd up` re-adopts them and re-grants the creator's session caps.
Agents that died while the daemon was down are dropped on that restore.

Control Panel pairing (ids + peer public keys only; no TTY) is specified in
[requirements/control-plane-pairing.md](requirements/control-plane-pairing.md).
Session aliases, the recent-session placeholder, and the **session catalog** are
client-local (`aliases.json` / `recent.json` / `sessions.json`).
`tyd session list` reads the catalog only — it contacts neither the Control Panel
nor any daemon. Create records the dial address when known; attach and close reuse it.

Layers from bottom to top:

| Layer | Responsibility |
|-------|----------------|
| Session / PTY | Create, I/O, resize, signal, close; survive client and daemon restarts |
| AuthZ | Capabilities: list, create, attach, write, resize, signal, close |
| AuthN | Ed25519 identity; trust file of public keys |
| Protocol | Shared frames over any byte stream |
| Transport | How the stream is obtained: `unix`, `tls`, `quic`, or `relay` |

## Data plane

After pairing, peers form a 1:1 data plane. Clients try the QUIC candidates the
server published, then fall back to the `tyd-relay` rendezvous (default
`https://app.getfda.dev/relay`) when every direct dial fails. Session bytes never
pass through the Control Panel. Phase status — QUIC direct done, relay MVP done,
WireGuard planned: [requirements/dataplane-networking.md](requirements/dataplane-networking.md).

## Process model

- One binary: `tyd`
- `tyd up` supervises sessions on the **target** (daemon) host
- Other subcommands are clients; a client host need not run a resident daemon to
  `session list` or to dial a peer. Local `session create` / `attach` / `watch` /
  `close` start `tyd up` on demand when the unix socket is down.
- Client disconnect or `Ctrl-\` detach does **not** kill the shell
- Daemon restart keeps sessions whose live-agent is still alive; it does not keep
  the client catalog authoritative (it is advisory and client-local)

## Security model

1. **Transport confidentiality (TLS/QUIC path):** TLS 1.3 minimum; the client pins
   the server certificate fingerprint. Plain TCP is not a peer data-plane mode, and
   the relay is a blind WebSocket splice behind edge TLS.
2. **Identity:** Every connection must complete an Ed25519 challenge-response
   against `trusted.json`.
3. **Authorization:** Global caps (`list`, `create`) vs session-bound caps
   (`attach`, `write`, …). Creating a session grants the creator owner caps on that
   session **in the running daemon only** — they are re-derived on restore, never
   written back to `trusted.json`.

## Explicit non-goals

- SSH as a dependency or protocol
- Embedding Tailcat / NetBird / STUN **inside** the tyd binary (the relay is a
  WebSocket rendezvous: default CP `/relay`, optional separate `tyd-relay`)
- Unix user switching (UID/GID) for shells
- Durable audit log of terminal contents
- Server-side session database (the session catalog is client-local and advisory)
- Multiple simultaneous writers on one session
- File transfer, port forward, non-interactive command API
- Putting session/TTY bytes through the Control Panel
