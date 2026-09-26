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
6. Speaks over a local Unix socket, optional TLS TCP, QUIC peer data-plane, and relay fallback

FDA-facing features (file transfer, non-interactive exec, approval workflows, mesh networking) are **out of scope** for tyd. They can sit on top of it.

## Architecture

```text
  tyd CLI (keygen / up / register / accept / alias / status / session …)
           │
           │  Transport: unix | tls (opt-in) | quic (peer DP) | relay (fallback)
           │  Frame protocol (length-prefixed JSON)
           │  Ed25519 challenge-response
           ▼
        ┌─────┐         optional rendezvous
        │ tyd │  up  ───▶  tyd-relay (blind splice; not CP)
        └──┬──┘
           │  reconnects on restart
           ▼
     live-agent (per session, under ~/.tyd/live/<id>/)
           │
        PTY master → PTY slave → /bin/bash (or $SHELL)
```

Graceful `tyd up` stop (SIGINT/SIGTERM) leaves live-agents running so the next
`up` can restore the same shells and re-grant the creator’s session caps.
Hard kill is best-effort: dead agents are dropped on restore.

Control Panel pairing (ids + peer public keys only; no TTY) is documented in
[requirements/control-plane-pairing.md](requirements/control-plane-pairing.md).
Session aliases, recent-session placeholders, and the **session catalog** are
client-local (`aliases.json` / `recent.json` / `sessions.json`).
`tyd session list` reads the catalog only — it does not contact the Control Panel
or any daemon. Create writes the catalog (including the dial address when known);
attach/close reuse that address when present.

Layers from bottom to top:

| Layer | Responsibility |
|-------|----------------|
| Session / PTY | Create, I/O, resize, signal, close; survive client drop |
| AuthZ | Capabilities: list, create, attach, write, resize, signal, close |
| AuthN | Ed25519 identity; trust file of public keys |
| Protocol | Shared frames over any byte stream |
| Transport | How the stream is obtained: `unix`, `tls`, `quic`, or `relay` |

Connectivity overlays (WireGuard Phase 2, QUIC Phase 1, separate relay Phase 3)
are described in [requirements/dataplane-networking.md](requirements/dataplane-networking.md).
QUIC direct is preferred after pairing; if candidates fail, clients fall back to
`tyd-relay` (default `https://relay.getfda.dev`). WireGuard is not done yet.

## Process model

- One binary: `tyd`
- `tyd up` holds sessions in memory on the **target** (daemon) host
- Other subcommands are clients; a client host need not run a resident daemon to
  `session list` or to dial a peer. Local `session create` / `attach` / `watch` /
  `close` start `tyd up` on demand when the unix socket is down.
- Client disconnect or `Ctrl-\` detach does **not** kill the shell
- Daemon restart **does** drop in-memory sessions on that host (client catalog may still list them)

## Security model (completed)

1. **Transport confidentiality (TLS/QUIC path):** TLS 1.3 / QUIC; client pins server certificate fingerprint. Plain TCP is not a supported peer data-plane mode (relay path is a blind splice under edge TLS).
2. **Identity:** Every connection must complete Ed25519 challenge-response against `trusted.json`.
3. **Authorization:** Global caps (`list`, `create`) vs session-bound caps (`attach`, `write`, …). Creating a session grants the creator owner caps on that session **in memory** only.

## Explicit non-goals (so far)

- SSH as a dependency or protocol
- Embedding Tailcat / NetBird / STUN **inside** the tyd binary (relay is a **separate** `tyd-relay` deployable)
- Unix user switching (UID/GID) for shells
- Durable audit log of terminal contents
- Session restore after daemon restart
- Multiple simultaneous writers on one session
- File transfer, port forward, non-interactive command API
- Putting session/TTY bytes through the Control Panel
