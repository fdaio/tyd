# Data-plane networking after pairing

> Historical requirements document (REQ-110) for the peer data plane. For how it
> behaves today, read [operations.md](../operations.md); for implementation
> status see [roadmap.md](../roadmap.md).

Product decision (REQ-110): after Control Panel pairing, peers form a **1:1 data plane**
inside tyd. Keys reuse the existing Ed25519 pair identity.

## Phases

| Phase | Transport | Status |
|-------|-----------|--------|
| **1** | **QUIC direct** | Done — clients try published candidates in order, then use the Phase 3 relay if every candidate fails |
| **2** | WireGuard | Planned |
| **3** | Relay | MVP done — WebSocket on CP `/relay` (+ optional `tyd-relay`); direct first, relay as fallback |

## Hard rules

- Session / TTY bytes **never** go through Control Panel.
- The relay is a separate data path: the CP may host `/relay`, but it keeps only
  pairing metadata and never sees or stores session bytes.
- Topology is **1:1** per pair (not a full mesh yet).

## Lifecycle

| Command | Role |
|---------|------|
| `tyd up` | Daemon; keep CP registration/peers in sync; listen + publish data-plane candidates; offer on `--relay` |
| `tyd register` / `tyd accept` | Establish pair; once both sides `up`, DP uses published candidates (no manual `--advertise` required for LAN/same-host) |
| `tyd-relay` / CP `/relay` | Blind WebSocket splice (TLS at edge); default URL `https://app.getfda.dev/relay` |

## Phase 1 behavior

1. When registered, `tyd up --data-listen auto` listens **QUIC** on `0.0.0.0:0` (all interfaces).
2. Publishes to CP: primary `addr`, `cert_fp`, `transport=quic`, plus `candidates` (interface IPs + optional `--advertise` + loopback for local tests).
3. **Create** (and attach/watch/close when the catalog has no dial addr yet) resolve the peer endpoint from CP and **try candidates in order** until dial + AuthN succeed.
4. Successful **create** records the dial target in the client catalog (`~/.tyd/sessions.json`); later attach prefers that address.
5. **`session list` does not use CP or the data plane** — it is a local catalog read.
6. If every direct candidate fails → **relay fallback** (Phase 3 MVP) when `--relay` is not `off`.

## Phase 3 MVP (relay)

Tailcat-like behavior without DERP/WireGuard:

1. Prefer CP `/relay` (WebSocket) at the Control Panel origin; optional dedicated `tyd-relay` (compose `relay`) behind TLS.
2. Server: `tyd up` keeps an outbound **offer** on the relay keyed by daemon id.
3. Client: after direct QUIC candidates fail (or CP has no endpoint), dials the relay with the peer id over **WebSocket**; relay notifies the server, splices the two streams.
4. Existing Ed25519 AuthN + session frames run end-to-end over the splice (relay is blind to TTY).
5. `--relay URL` overrides the default; `--relay off` disables fallback and offering.

## Out of Phase 1 / this MVP

- STUN / ICE hole punching across strict NATs
- WireGuard
- Upgrading an active relay path to direct mid-session
