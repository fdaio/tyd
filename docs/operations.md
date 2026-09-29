# Operating tyd

## Build from source

```bash
git clone git@github.com:fdaio/tyd.git && cd tyd
make test
make build          # ./tyd
make install        # ~/.local/bin/tyd
make fmt            # gofmt the tree
make controlpanel   # ./controlpanel
make dist           # ./dist/tyd-<os>-<arch>.tar.gz release archives
make dist-relay     # ./dist/tyd-relay-<os>-<arch>.tar.gz relay archives
```

`make install` copies the `tyd` binary to `$(PREFIX)/bin` (`PREFIX` defaults
to `~/.local`) and starts the per-user daemon, which stays up after logout.
Set `DESTDIR` to stage a packaging root without starting a daemon.
`controlpanel` is a separate binary and is not installed.

## Daily release

GitHub Actions workflow `Release` runs every day at 23:00 Asia/Shanghai
(`0 15 * * *` UTC), and can be started by hand. The version is the Shanghai
calendar date plus the 7-character commit id, for example `2026.09.27-19d5e02`.

It publishes one GitHub Release of `main` when that commit is not already tagged
in this form. The install archives are `tyd-<os>-<arch>.tar.gz` — one per
platform, each holding a single `tyd`, plus `tyd-relay-<os>-<arch>.tar.gz` for
the relay. `install.sh` downloads the one asset that matches the machine it
runs on (about 3.7MB; the per-OS archive it replaced was 12.4MB and carried the
other architecture and the relay as well). A manual tag such as `v0.1.0` is not
a daily version. If `main` has no new commit since the last daily tag, the
workflow succeeds and skips the build and the release.

Because the archive name now includes the architecture, an `install.sh` copied
before this change asks for `tyd-<os>.tar.gz` and fails after the next daily
release. Fetch the script again (`curl -fsSL https://app.getfda.dev/install.sh | sh`).

## Run the daemon

```bash
tyd up
```

`tyd serve` is a deprecated alias for `tyd up`.

By default tyd listens on the Unix socket `~/.tyd/tyd.sock` and **nothing else** —
TLS is opt-in, and the QUIC data plane only starts for a registered daemon.

```bash
tyd up                                            # unix only (default)
tyd up --listen 127.0.0.1:61211                   # enable TLS
tyd up --socket /tmp/tyd.sock --trust /path/trusted.json
tyd up --tls-cert /path/server.crt --tls-key /path/server.key
tyd up --data-listen off                          # no peer data plane
tyd up --audit-log ~/.tyd/audit.log               # control-event audit trail
tyd up --session-idle-timeout 8h                  # reap unattended sessions
tyd up --session-output-log-max 64MB              # per-session output log cap (default)
```

## Data plane and relay

A registered `tyd up` starts a **QUIC** listener on all interfaces (`0.0.0.0:0`)
and publishes its address, candidates, and certificate fingerprint to the Control
Panel (`transport=quic`, ephemeral signaling only, refreshed about every 30 seconds
and expiring after about 90). Clients try candidates in order, then fall back to the
relay.

```bash
tyd up --data-listen auto                     # default: 0.0.0.0:0 when registered, off otherwise
tyd up --data-listen 0.0.0.0:61212            # fixed host:port
tyd up --data-listen off                      # no peer data plane
tyd up --advertise example.com                # put this host first in candidates
tyd up --relay off                            # no rendezvous offer or fallback
tyd up --relay http://127.0.0.1:8080/relay    # local Control Panel relay
tyd up --relay https://relay-1.example,https://relay-2.example   # several
```

The relay is a blind WebSocket splice, and the two peers negotiate TLS 1.3
inside it, so what the relay carries is ciphertext. Each side proves its
Ed25519 identity over the TLS exporter, which is also what stops a relay from
re-terminating TLS to impersonate a peer. See
[protocol.md](protocol.md#relay-path-security) for the full boundary, including
the metadata a relay can still observe. While a splice is up, the relay pings
each WebSocket leg every 15s.
Those frames stay out of the terminal byte stream and keep a quiet session from
being cut by Cloudflare's idle timeout (about 100s). The default is the Control
Panel's own `/relay`
(`https://app.getfda.dev/relay`); a dedicated process is optional
(`make relay`, `go run ./cmd/relay`, or the compose `relay` service). Phase
status:
[requirements/dataplane-networking.md](requirements/dataplane-networking.md).

### More than one relay

`--relay` takes a comma-separated list. `tyd up` offers on every entry
concurrently and independently, so one unreachable relay does not disturb the
others, and clients walk the same list in order when they fall back.

The relays share no state: an offer lives in the process it registered with, and
a ticket is only ever claimed on that same process. There is no clustering, no
load balancer, and no shared database — which is also why you cannot put several
replicas behind a round-robin proxy. Give each relay its own hostname and list
them all.

```bash
tyd up --relay https://relay-1.example,https://relay-2.example
tyd status | rg relay                                     # shows the list
```

Clients need the same list. A client that only knows one relay can still reach a
server that offers on several; the reverse does not hold.

Note what this does **not** buy: a session already spliced through a relay dies
with that relay process, because its bytes flow through that process. Surviving
*live* sessions is a separate design step, tracked in
[requirements/dataplane-networking.md](requirements/dataplane-networking.md).

A relay does report the address it observed for each side of a call — the
post-NAT source it actually received, rather than a self-reported interface IP.
It is recorded and logged, never dialled: sessions still run over the splice,
unchanged. The client needs `--verbose` to show it:

```
debug1: Relay observed peer at 203.0.113.7:41234 via https://relay-1.example.
```

The server logs the client side on stderr:

```
tyd relay client observed at 198.51.100.9:51234 via https://relay-1.example
```

#### Running a relay fleet

One relay per host, on separate failure domains. Two relays in containers on the
same machine are not redundant — they die together.

Build the binary (each release also ships `tyd-relay-<os>-<arch>.tar.gz`, so a
relay host needs no Go toolchain):

```bash
make relay                              # or: go build -o tyd-relay ./cmd/relay
```

Run it bound to loopback and let a TLS proxy face the internet. The relay serves
plain HTTP and prints a warning to that effect; it also has no authentication at
the WebSocket layer, so do not skip the usual edge hardening.

```ini
# /etc/systemd/system/tyd-relay.service
[Unit]
Description=tyd relay
After=network.target

[Service]
ExecStart=/opt/tyd/tyd-relay -listen 127.0.0.1:9090
Restart=always
User=tyd
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```caddyfile
relay-1.example {
    reverse_proxy 127.0.0.1:9090
}
```

`https://` URLs are upgraded to `wss://` automatically, so the client and the
server need nothing but the list:

```bash
tyd up --relay https://relay-1.example,https://relay-2.example
tyd --relay https://relay-1.example,https://relay-2.example session create --peer laptop
```

`curl -s https://relay-1.example/healthz` returns `ok`. A live server should log
one `relay offering` line per relay.

To run the relay in a container instead, use the compose profile:

```bash
docker compose --profile standalone-relay up -d --build
```

#### If the image build cannot reach the Go module proxy

`go mod download` inside the build talks to `proxy.golang.org`. A host with a
flaky or blocked route to it fails partway through the build like this:

```
18.90 go: github.com/coder/websocket@v1.8.15: Get
  "https://proxy.golang.org/...": net/http: TLS handshake timeout
```

This is a network problem, not a tyd problem. First just retry — a single
handshake timeout is often transient. If it persists, either point the build at
a proxy this host can reach (`GOPROXY` is passed through; unset keeps the
toolchain default):

```bash
GOPROXY=https://your-proxy.example,direct docker compose --profile standalone-relay up -d --build
make docker-source GOPROXY=https://your-proxy.example,direct   # Control Panel
```

or skip the module fetch altogether. `make relay-image` compiles on the host and
packs the result, so nothing is downloaded inside Docker:

```bash
make relay-image   # or: docker build -f Dockerfile.relay.prebuilt -t tyd-relay:local .
```

That is also the fast path on a 1C/1G VPS where an in-Docker compile is slow.

## Docker Compose (Control Panel)

```bash
cp .env.example .env      # optional: TYD_CP_BASE_URL / TYD_CP_PORT / TYD_RELAY_PORT
make dist   # tyd-<os>-<arch>.tar.gz; install.sh downloads these from GitHub Releases
docker compose up -d --build
curl -s http://127.0.0.1:8080/healthz
```

Notes:

- The default build compiles **inside** the golang stage, so classic Compose works
  without buildx or a host Go toolchain. With Go on the host, `make docker`
  compiles once and `docker compose up -d` just packs the image.
- `install.sh` is still served at `/install.sh`. The binary is downloaded from
  `https://github.com/fdaio/tyd/releases/latest/download/tyd-<os>-<arch>.tar.gz`.
- `--platform` is only needed for a custom or local Control Panel.
- The container listens on `0.0.0.0:8080` with no TLS — terminate at the edge
  (e.g. Cloudflare). Compose caps it at 0.5 CPU and 128 MB.
- **Control Panel state is in-memory only.** A container restart drops
  registrations, invites, and peer pairs; daemons restore from local `peers.json`
  on their next `tyd up`. The relay holds no durable session state.
- Optional dedicated relay: `docker compose --profile standalone-relay up -d --build`.

## When the disk fills up

State files under `~/.tyd` are a cache of what the daemon already holds in memory
and what the Control Panel already knows. A failing disk degrades tyd; it does not
stop it.

- **Writes never destroy the previous file.** Every state file is written to a
  temporary file and renamed into place, so a failed write leaves the last good
  version intact.
- **Memory is authoritative.** The daemon reads `peers.json` once at startup. The
  maintenance loop works from memory, retries the write each tick, and says so
  once when the file becomes writable again. Paired peers keep their access while
  the disk is full.
- **`paired.json` is the trust record, and it is local.** `peers.json` is
  rebuilt from the Control Panel on every sync, so a peer listed there is a peer
  the Control Panel asked for. Trust comes from `paired.json` instead, written
  only by pairing and checked against a secret the Control Panel never sees. A
  peer it starts listing gains nothing; a peer it stops listing loses trust. On
  the first run after an upgrade the existing peers are adopted once as `legacy`
  so nobody is cut off — `tyd peer show` marks those, and their trust still
  rests on the Control Panel until they are paired again.
- **Published endpoints are signed, and the signed values are the ones dialled.**
  A daemon signs the address, certificate fingerprint, candidate list, expiry and
  sequence it publishes; a client verifies that signature against the pinned peer
  key before connecting. The Control Panel can carry, withhold or expire a
  record, and can shorten its life, but it cannot alter one, and a client that
  receives a record with no usable signature falls back to the relay rather than
  dialling it. The highest sequence already accepted per peer is kept in
  `paired.json`, so a replayed-but-authentic record is refused across restarts.
- **A damaged `peers.json` is set aside, not trusted.** On startup the file is
  renamed to `peers.json.corrupt.<timestamp>` and the registration and peer list
  are pulled back from the Control Panel using this daemon's identity. The daemon
  id and the pairings survive, and the approval mode is taken from the Control
  Panel rather than reset — recovery never relaxes a `pre` or `post` daemon to
  `full`.
- **Audit write failures warn once** and sessions carry on.
- **Output-log write failures** stop new disk segments and keep the PTY on the
  64KB ring. `tyd doctor` reports `output.err` in the session dir. This is not
  the audit chain; terminal bytes never enter `--audit-log`.

If the Control Panel is also unreachable, the daemon keeps serving local sessions
and tells you to run `tyd doctor --fix` once the disk is healthy.

### `tyd doctor`

```bash
tyd doctor         # check state files, free space, writability, and output-log write failures
tyd doctor --fix   # set a damaged peers.json aside and rebuild it from the CP
```

`doctor` loads each file the way tyd does, so it reports the real failure rather
than just "file exists". It exits non-zero when something is broken:

```
ok   disk             38.3 GiB free on /home/user/.tyd
ok   writable         /home/user/.tyd
fail peers            /home/user/.tyd/peers.json: empty (truncated by a failed write?)
```

## Status

```bash
tyd status
```

Prints:

1. **Control Panel** — platform URL, relay URL, registration id/url, approval mode,
   published data-plane endpoint (if any)
2. **Peers** — paired peer ids, nicknames, direction, paired-at
3. **Recent** — last peer / session used by this client (`~/.tyd/recent.json`)
4. **Session aliases** — local names from `~/.tyd/aliases.json`
5. **Connections** — live daemon connections (transport, remote, TLS, principal, attached session)

Connections require a reachable daemon and the `list` capability. The Control Panel
and peers sections come from local files (plus an optional endpoint lookup) even if
the daemon is down.

## TLS client

Copy the server's `server.crt` to the client machine, then:

```bash
tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt session create
tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt status
tyd --addr 127.0.0.1:61211 --tls-cert /path/to/server.crt session attach <id>
```

With `--addr`, the client uses TLS and ignores `--socket` for that command. It
**pins** the certificate fingerprint; a different certificate is rejected
(`untrusted server certificate`).

## Trust and permissions

### `trusted.json` shape

```json
{
  "principals": [
    {
      "name": "local",
      "public_key": "<base64 ed25519 public key>",
      "allow": ["list", "create"],
      "sessions": {
        "optional-session-id": ["attach"]
      }
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `allow` | Global: only `list`, `create` |
| `sessions` | Optional map of `session_id` → caps |

Session caps: `attach`, `write`, `resize`, `signal`, `close`. `attach` does not
imply `write`. A key that is not listed fails the handshake with
`untrusted public key`.

## Testing trust and TLS locally

```bash
tyd --identity /tmp/tyd-a --trust /tmp/trust-a.json keygen
tyd --socket /tmp/tyd.sock --trust /tmp/trust-a.json --listen off up
# other terminal:
tyd --identity /tmp/tyd-b --trust /tmp/trust-b.json keygen
tyd --socket /tmp/tyd.sock --identity /tmp/tyd-b session create --detach   # expect: untrusted
```

Automated coverage: `go test ./internal/auth ./internal/server ./internal/transport`.

## See also

- [connect.md](connect.md) — pairing and first connection
- [session.md](session.md) — session lifecycle, aliases, approval modes
- [cli.md](cli.md) — full command and flag reference
