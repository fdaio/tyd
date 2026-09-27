# Operating tyd

## Build from source

```bash
git clone git@github.com:fdaio/tyd.git && cd tyd
make test
make build          # ./tyd
make install        # ~/.local/bin/tyd
make fmt            # gofmt the tree
make controlpanel   # ./controlpanel
make dist           # ./dist/tyd-<os>.tar.gz release archives
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
in this form. The archives are `tyd-linux.tar.gz`, `tyd-darwin.tar.gz`, and
`tyd-freebsd.tar.gz`. `install.sh` downloads the latest of those assets. A
manual tag such as `v0.1.0` is not a daily version. If `main` has no new commit
since the last daily tag, the workflow succeeds and skips the build and the
release.

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
```

The relay is a blind WebSocket splice, so authentication and session frames stay
end-to-end. The default is the Control Panel's own `/relay`
(`https://app.getfda.dev/relay`); a dedicated process is optional
(`go run ./cmd/relay` or the compose `relay` service). Phase status:
[requirements/dataplane-networking.md](requirements/dataplane-networking.md).

## Docker Compose (Control Panel)

```bash
cp .env.example .env      # optional: TYD_CP_BASE_URL / TYD_CP_PORT / TYD_RELAY_PORT
make dist   # tyd-<os>.tar.gz; install.sh downloads these from GitHub Releases
docker compose up -d --build
curl -s http://127.0.0.1:8080/healthz
```

Notes:

- The default build compiles **inside** the golang stage, so classic Compose works
  without buildx or a host Go toolchain. With Go on the host, `make docker`
  compiles once and `docker compose up -d` just packs the image.
- `install.sh` is still served at `/install.sh`. The binary is downloaded from
  `https://github.com/fdaio/tyd/releases/latest/download/tyd-<os>.tar.gz`.
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
- **A damaged `peers.json` is set aside, not trusted.** On startup the file is
  renamed to `peers.json.corrupt.<timestamp>` and the registration and peer list
  are pulled back from the Control Panel using this daemon's identity. The daemon
  id and the pairings survive, and the approval mode is taken from the Control
  Panel rather than reset — recovery never relaxes a `pre` or `post` daemon to
  `full`.
- **Audit write failures warn once** and sessions carry on.

If the Control Panel is also unreachable, the daemon keeps serving local sessions
and tells you to run `tyd doctor --fix` once the disk is healthy.

### `tyd doctor`

```bash
tyd doctor         # check state files, free space, and writability
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
