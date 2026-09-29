# CP maintenance: one request a round, and a restart that heals

Goal: a Control Panel can be redeployed without anyone touching the fleet, and
a fleet of any size costs it as little as one request per interval per machine.

## The problem

The Control Panel holds registrations, invites, published endpoints and relay
tickets **in memory** (`docs/operations.md`), so a restart — a deploy, a crash,
a reboot — drops all of it. Each daemon polls it every 30s, and every poll
answered 404, because an unknown registration 404s both the peer list and the
endpoint publish. The daemon had no path back: the only place it re-registered
was `tyd up` at startup (`ensureCPRegistration`), and the install unit is
`Restart=on-failure`, so nothing restarted it.

The result was invisible and permanent. Published endpoints carry a ~90s TTL
and are refreshed every 30s, so a fleet that cannot publish has no direct QUIC
path at all — every client silently falls back to the relay through Cloudflare,
and stays there until a person restarts `tyd up` on every host. The only trace
was one 404 per 30s on each daemon's stderr, in a file nobody reads.

## Mechanism

**A 404 is the trigger, and the restore is the fix.** `ensureCPRegistration` was
already there and already idempotent: it restores the registration and peer list
from local `peers.json`, and `Service.Restore` is keyed by the daemon's own id
and public key, so it can only restate what that identity already had. Calling it
from the poll loop gives the automatic path exactly the authority the startup
path has, and no more. Trust is unaffected either way — it comes from
`paired.json`, which is local.

**The retry is part of the fix.** Restoring without retrying would leave the
endpoint unpublished for another interval, and the endpoint is what a client
dials directly. So the round is re-run, and the publish goes out in the same
pass. Cost of healing: four requests instead of one, once per Control Panel
restart.

**One request per round.** The daemon needs the peer list and the endpoint on
every interval, so `PUT /v1/daemons/{id}/sync` takes both: it publishes the
endpoint and returns the peer list. It calls the same `PublishEndpoint` and
`ListPeers` the two existing routes do, not a copy, so the proof checks, the
public-key match and the TTL cap cannot drift between them. The two take the
lock separately — a peer list one instant stale is what a second request would
have returned anyway, and holding the lock across both would serialise every
daemon's round against every other one's.

**The load arithmetic, measured.** `rg NewTicker` finds three loops, all in
`tyd up`: the 30s Control Panel poll, a 2s loop that only reads local state, and
a 1s loop inside the `invite` command. Clients do not poll at all — `endpoint()`
resolves a peer once per dial, and an attached or detached session makes no
requests. So the fleet costs 2 requests / 30s / **machine** (4 req/min), which
for the four machines in use here is 16 req/min. What scales badly is not the
request count but the long-lived relay WebSocket each daemon holds: 1000
machines is 67 req/s (trivial) and 1000 open connections (not trivial).

**Backoff, because a fixed ticker is a bug.** The poll was `time.NewTicker(30s)`
with no failure handling, so a Control Panel that was down got dialled on that
timer indefinitely, each attempt carrying a 15s timeout
(`cpclient.New`). Failure now walks 30s → 1m → 2m → 5m and resets on success.
A Control Panel that is *unreachable* therefore costs less traffic than it did
before this change.

**Jitter, because the fleet is already synchronised.** Endpoints expire on a
shared TTL, so daemons started together arrive together and every 30s is a
spike. Each wait carries ±20% jitter.

**The old-Control-Panel path.** `install.sh` upgrades daemons on their own
schedule while a self-hosted Control Panel is redeployed by hand, so a daemon
outliving the Control Panel it was built for is ordinary. A 404 there would
otherwise be read as a lost registration, and the daemon would republish into a
404 forever — the exact failure this change exists to remove, reproduced. The
restore disambiguates for free, because it starts by asking for the peer list
this daemon id already had: known daemon + 404 means the route is missing, so
the daemon says so once and keeps using the two requests. Unknown daemon + 404
is the real thing, and gets restored.

**The pool on purpose.** The CP client leaned on `http.DefaultTransport` for
connection reuse. That works by accident and leaves the pool untunable;
`internal/cpclient` now clones the default transport with a wider idle pool,
which is the right size for a poller that is also its own only client.

## Invariants

1. A healthy round costs exactly one request and issues no restore.
2. A 404 is answered with a restore and the round is retried, so the endpoint,
   fingerprint and candidates are back in the same pass.
3. Recovery never widens access: restore is keyed by this daemon's own id and
   public key, and trust is rebuilt from `paired.json`, never from what the
   Control Panel returned.
4. A Control Panel that is up but unwell (anything but a 404) gets no restore
   attempt — it would answer the same way. The backoff decides when to look
   again.
5. A daemon newer than its Control Panel keeps publishing, over two requests,
   and says so once.
6. Trust is rebuilt whether or not the round reached the Control Panel, so one
   that is down cannot delay a revocation a local `tyd revoke` already recorded.
7. Backoff never exceeds 5m and resets on the first success; every wait stays
   within ±20% of its nominal value.
8. Nothing here touches a session. Live-agents are unaffected; a splice through
   a restarted Control Panel drops and is re-established on the next `attach`.
9. `/sync` enforces exactly what `/endpoint` enforces: no proof, or a proof that
   does not cover the published address or fingerprint, is refused and stores
   nothing.

## Also in this PR

- `ensureCPRegistration` returns the id it restored instead of printing it, so
  the same restore reads differently at startup and mid-poll.
- The schedule, the negotiated route and the recovery live in one small
  `cpPoll` type, kept off the clock so the backoff ladder is tested in
  microseconds rather than by waiting out an interval.
- `operations.md` no longer tells an operator that daemons restore on their next
  `tyd up` — that sentence is what made a Control Panel restart look like a
  reason to want high availability.

## Out of scope

- **High availability.** Several Control Panel replicas behind a round-robin
  proxy break the relay handshake today (`unknown ticket`): offers and tickets
  live in one process. Doing it properly means shared state plus cross-process
  ticket forwarding, and the latter only makes the *dial entry point*
  redundant, not the byte path
  (`requirements/dataplane-networking.md` §4a/§4b).
- **Persisting Control Panel state.** A JSON snapshot would survive a container
  restart but not the host; the self-heal above already removes the operational
  need, and a snapshot is a second source of truth to keep honest.
- **Moving the peer list out of the round.** `/sync` is already one request; a
  separate `sync` endpoint that does not publish, for a daemon with no data
  plane, is not worth the extra route.
- **Lengthening the healthy interval.** 30s against a 90s TTL is a 3× margin.
  45s would save a third of the traffic, but the margin is the thing protecting
  a client from a missed refresh, and it belongs in one place — ideally a
  refresh interval the Control Panel reports, which is a later step.
- **The production deploy runbook.** Separate work; this change only removes
  the step in it that said "now restart `tyd up` on every host".
