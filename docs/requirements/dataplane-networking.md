# Data-plane networking after pairing

Product decision (REQ-110): after Control Panel pairing, peers form a **1:1 data plane**
inside tyd. Keys reuse the existing Ed25519 pair identity.

## Phases

| Phase | Transport | Status |
|-------|-----------|--------|
| **1** | **QUIC direct** | In progress — prefer direct; fail with error if unreachable |
| **2** | WireGuard | Planned |
| **3** | Relay | Planned — **separate deployable module**, never inside CP |

## Hard rules

- Session / TTY bytes **never** go through Control Panel.
- Relay (when built) is an independent service; CP stays pairing + ephemeral signaling only.
- Topology is **1:1** per pair (not a full mesh yet).

## Lifecycle

| Command | Role |
|---------|------|
| `tyd up` | Daemon; keep CP registration/peers in sync; listen + publish data-plane candidates |
| `tyd register` / `tyd accept` | Establish pair; once both sides `up`, DP uses published candidates (no manual `--advertise` required for LAN/same-host) |

## Phase 1 behavior

1. When registered, `tyd up --data-listen auto` listens **TLS** on `0.0.0.0:0` (all interfaces).
2. Publishes to CP: primary `addr`, `cert_fp`, `transport=tls`, plus `candidates` (interface IPs + optional `--advertise` + loopback for local tests).
3. **Create** (and attach/watch/close when the catalog has no dial addr yet) resolve the peer endpoint from CP and **try candidates in order** until dial + AuthN succeed.
4. Successful **create** records the dial target in the client catalog (`~/.tyd/sessions.json`); later attach prefers that address.
5. **`session list` does not use CP or the data plane** — it is a local catalog read.
6. If every candidate fails → clear error (no relay fallback in Phase 1).
7. **QUIC** listen/dial APIs (`transport.KindQUIC`) and unit tests are landed; flipping the default data-plane from TLS→QUIC is a follow-up once session accept-loop integration is hardened.

## Out of Phase 1

- Default-on QUIC data-plane (API ready; enable in follow-up)
- STUN / ICE hole punching across strict NATs (may still fail; error is OK for now)
- WireGuard
- Relay module
