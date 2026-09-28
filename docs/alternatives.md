# How tyd relates to tmux, mosh, and Tailscale SSH

[overview.md](overview.md) has the architecture; this page is about *when tyd is
the right tool and when it is not*. It is deliberately honest about overlap — in
several cases tyd is the wrong choice.

## One table

| | Session survives disconnect | Survives daemon/service restart | Native reattach semantics | Setup cost | Bytes through a third party |
|---|---|---|---|---|---|
| `ssh` alone | no | no | no | low | depends on your host |
| `tmux` over `ssh` | yes | yes, if the tmux server survives | partial — terminal state is not restored | low | depends on your host |
| `mosh` | yes, for roaming | no — new mosh spawns a new shell | no | medium | the roaming server, not a SaaS |
| Tailscale SSH | no — a disconnected session is gone | no | no | low, inside a tailnet | Tailscale coordination only |
| **tyd** | yes | yes, while the live agent process is alive | `session attach` reattaches a live PTY; `watch` shows it read-only | low | Control Panel (pairing) / relay (rendezvous) |

## tyd vs `tmux + ssh`

Both give you a shell that outlives the connection. The differences:

- **No SSH.** tyd speaks its own framed protocol over QUIC/TLS/relay. Nothing
  depends on `sshd`, keys, or `~/.ssh/config`. If you already have a working SSH
  setup, tyd is redundant here.
- **The shell is a supervised process.** Every session runs as a live agent
  process under the daemon, so `tyd up` can restart and re-adopt the survivors.
  tmux needs its own server for the same property.
- **Built-in session inventory.** `session list`, aliases (`tyd jammy.laptop`),
  and `session watch` for a read-only follow. tmux gives you `tmux ls` on the
  host, and only on the host.
- **What tmux does better:** scrollback and pane layout, split windows, terminal
  state restoration. tyd reattaches a live PTY; it does not replay what the
  terminal already drew.

**Use tyd** when you want sessions on a headless box that has no SSH exposure and
no terminal multiplexer, or you want a client on a device that only speaks tyd.
**Use tmux** when you already work over SSH and care about panes and scrollback.

## tyd vs mosh

Both are built for a bad network. The differences:

- **mosh roams** — it predicts your keystrokes and re-establishes a UDP session
  across IP changes. tyd does not do predictive echo or roaming; it reconnects to
  a live session from a new address, but the transport is a fresh QUIC or relay
  dial each time.
- **mosh is not a session manager.** A new `mosh` invocation is a new shell. tyd's
  session is a named, reattachable object with a catalog and aliases.
- **mosh runs over your existing SSH for the first hop.** tyd needs no SSH at all.

**Use mosh** for latency on a hostile link. **Use tyd** for a session you need to
come back to by name later. They compose: reach the host over WireGuard or
Tailscale, then attach with tyd.

## tyd vs Tailscale SSH

These are complementary, not alternatives. Tailscale solves *reachability*: it
gives both machines a private address and a stable identity, with ACLs and a
coordination server. Tailscale SSH then gives you a shell over that network.

tyd solves *session lifetime*: the shell keeps running when the client goes away,
and you reattach to the same PTY from a different machine later. A disconnected
Tailscale SSH session is gone, exactly like a disconnected `ssh` session — unless
you wrap it in tmux, at which point you have reimplemented the part tyd already
does.

The honest framing: **Tailscale gets you the connection; tyd gets you the session
that survives it.** Run tyd over a Tailscale network and the Control Panel is
still the default rendezvous, but both hosts are already on a private network and
you can point the data plane at a direct QUIC candidate.

**Use Tailscale alone** if you only need to reach a host and every session is
short-lived. That is most people's case, and it is a fine choice.

## The Control Panel caveat

This is the part the comparison tables usually skip.

Pairing requires a Control Panel. The default is fdaio's hosted one at
`app.getfda.dev`, so by default a third party sees:

- your daemon id, Ed25519 public key, registration time, and approval mode,
- for each peer: its id, public key, nickname, pairing time, and direction,
- your published endpoint: address, certificate fingerprint, transport, and the
  QUIC candidate list (these expire).

A relay you use sees, on top: both peers' IP addresses, when they connected,
byte counts and timing, and the daemon id, peer id and ticket it uses to match
the two sides. It does not see session content.

It stores **nothing about your sessions** — no session id, no alias, no command
history, no terminal output. The session catalog is client-local and advisory.

It never sees session or TTY bytes; the data plane is direct QUIC, or TLS 1.3
negotiated between the two peers across the relay's splice, which relays
ciphertext. A relay still sees connection metadata — addresses, timing, byte
counts, daemon and peer ids — and [protocol.md](protocol.md#relay-path-security)
sets out exactly what that is and is not.

To remove the hosted service from the path, run your own Control Panel and pass
`--platform` to both ends. The relay is separate, and `--relay` takes a
comma-separated list so you can run more than one. See [connect.md](connect.md)
and the compose recipe in [operations.md](operations.md). If you are willing to
run a VPN with ACLs instead, WireGuard or Tailscale may be the better first layer
and tyd the session layer on top.

## What tyd does not do

From [overview.md](overview.md#explicit-non-goals), so you do not go looking for
it: no SSH, no port forwarding, no file transfer, no non-interactive command API,
no user switching, no durable log of terminal contents, no multiple simultaneous
writers on one session, and no server-side session database — the catalog is
client-local and advisory. The roadmap is [roadmap.md](roadmap.md).
