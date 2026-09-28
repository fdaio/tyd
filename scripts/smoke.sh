#!/bin/sh
# Smoke test for a release, run before it is promoted to what installs fetch.
#
# This is deliberately the whole path a user takes, from curl to a session that
# exists: install the real archive, start the daemon, mint an invite, accept it
# from a second identity on the same host, create a session, and see it listed.
# The pairing is loopback on purpose -- it exercises both halves of the pairing
# code (secret, signatures, the Control Panel round trip) without needing a peer
# machine, which is exactly the part a build breaks most often.
#
# Everything happens under a scratch HOME, so a runner's own state is untouched
# and the test says so when that is not possible.
#
# Usage: smoke.sh <release-url>          # install from a specific tag's asset
#        smoke.sh --channel edge         # install from the newest prerelease
set -eu

say() { printf '  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
	printf '\nsmoke: %s\n' "$*" >&2
	exit 1
}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
linux | darwin) ;;
*) die "unsupported host $OS" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "unsupported arch $(uname -m)" ;;
esac

RELEASE_URL=""
case "${1:-}" in
--channel)
	CHANNEL="edge"
	;;
--channel=*)
	CHANNEL="${1#--channel=}"
	;;
"")
	die "usage: smoke.sh <release-url> | smoke.sh --channel [stable|edge]"
	;;
*)
	RELEASE_URL="$1"
	;;
esac
[ -n "${CHANNEL:-}" ] || CHANNEL=stable

WORK=$(mktemp -d)
cleanup() {
	# The daemon has to be asked to stop before its scratch home disappears, or
	# it lingers holding a deleted socket.
	if [ -S "$WORK/home/.tyd/tyd.sock" ]; then
		"$WORK/home/.local/bin/tyd" --socket "$WORK/home/.tyd/tyd.sock" doctor >/dev/null 2>&1 || true
	fi
	pkill -f "$WORK/home/.local/bin/tyd" >/dev/null 2>&1 || true
	# The Control Panel has to be stopped explicitly. Left alone it dies with the
	# shell's process group anyway -- but only after the test is over, and a CP
	# that vanishes mid-test takes the daemon's peer sync with it, which looks
	# exactly like a build where pairing is broken.
	[ -n "${CP_PID:-}" ] && kill "$CP_PID" >/dev/null 2>&1 || true
	# SMOKE_KEEP=1 leaves the scratch tree behind, which is the only way to read
	# the daemon log and the Control Panel log after a failure.
	if [ "${SMOKE_KEEP:-0}" = "1" ]; then
		printf 'smoke: scratch tree kept at %s\n' "$WORK" >&2
		return
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT INT HUP

# A Control Panel of our own, on loopback: the hosted one is not part of what we
# are testing, and depending on it would make a smoke test fail for the wrong
# reason.
#
# It is built before HOME moves, because HOME is where the Go module cache
# lives. Scoping the install to a scratch home and then compiling would download
# the world again -- or, on a runner with a cold cache and a slow link, fail for a
# reason that has nothing to do with the release.
step "build a Control Panel to pair against"
go build -o "$WORK/controlpanel" ./cmd/controlpanel || die "cannot build the control panel"

# ---- 1. install, the way a user does -----------------------------------------

file_size() {
	[ -f "$1" ] || { printf '0\n'; return; }
	wc -c <"$1" | tr -d ' \t'
}

step "install ($OS/$ARCH, channel $CHANNEL)"
mkdir -p "$WORK/home"
# HOME is what decides where the install lands, so the whole install is scoped by
# it. TYD_BINDIR is set as well because a runner's PATH may already carry a tyd.
export HOME="$WORK/home"
export TYD_BINDIR="$HOME/.local/bin"
mkdir -p "$HOME"

# Port 0 and read the address back, rather than picking a number: a fixed port
# collides with whatever else the machine is running, and the collision is silent
# in the worst way -- another process answers /healthz and the test then pairs
# against a Control Panel that is not this one.
"$WORK/controlpanel" --listen "127.0.0.1:${SMOKE_CP_PORT:-0}" >"$WORK/cp.log" 2>&1 &
CP_PID=$!
PLATFORM=""
i=0
while [ "$i" -lt 100 ]; do
	PLATFORM=$(sed -n 's#^tyd control panel listening on \(http://[^ ]*\).*#\1#p' "$WORK/cp.log" 2>/dev/null | head -1)
	[ -n "$PLATFORM" ] && break
	i=$((i + 1))
	sleep 0.2
done
[ -n "$PLATFORM" ] || die "control panel did not report an address: $(cat "$WORK/cp.log" 2>/dev/null)"
i=0
while [ "$i" -lt 100 ]; do
	if curl -fsS --max-time 2 "$PLATFORM/healthz" >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	sleep 0.2
done
[ "$i" -lt 100 ] || die "control panel did not answer /healthz at $PLATFORM"
say "$PLATFORM"

# An explicit URL is what the promote workflow passes, so the test installs the
# exact build being promoted. Otherwise the installer resolves the channel, which
# is the path a user takes.
if [ -n "$RELEASE_URL" ]; then
	export TYD_RELEASE_URL="$RELEASE_URL"
	sh scripts/install.sh --no-daemon >"$WORK/install.out" 2>"$WORK/install.err"
else
	export TYD_PLATFORM="$PLATFORM"
	sh scripts/install.sh --no-daemon --channel "$CHANNEL" >"$WORK/install.out" 2>"$WORK/install.err"
fi
# --no-daemon installs the binary without touching the per-user service, and the
# daemon is started below with this HOME. The service cannot be used here: a
# launchd or systemd --user unit runs with the account's own environment whatever
# HOME says, so it would bind the runner's real socket instead of the scratch one
# and the test would wait forever.
[ $? -eq 0 ] || die "install failed:
$(cat "$WORK/install.err" 2>/dev/null)
$(cat "$WORK/install.out" 2>/dev/null)"
[ -x "$TYD_BINDIR/tyd" ] || die "no tyd at $TYD_BINDIR after install"
say "installed $(file_size "$TYD_BINDIR/tyd") bytes at $TYD_BINDIR/tyd"

# ---- 2. register and offer --------------------------------------------------

step "register the server"
# --no-wait: register otherwise mints an invite and blocks until somebody accepts,
# which is the next step, not this one.
"$TYD_BINDIR/tyd" --platform "$PLATFORM" --data-listen 127.0.0.1:0 register --no-wait >"$WORK/register.out" 2>&1 ||
	die "register failed: $(cat "$WORK/register.out")"

step "start the daemon"
# The data plane is on because that is what a real server runs, and because the
# peer sync that makes an accepted peer visible is driven from there: with it off
# the daemon syncs the peer list once at startup and never again, so a peer
# accepted afterwards stays invisible until it is restarted.
"$TYD_BINDIR/tyd" --platform "$PLATFORM" --data-listen 127.0.0.1:0 up >"$WORK/up.out" 2>&1 &
i=0
while [ "$i" -lt 100 ]; do
	[ -S "$HOME/.tyd/tyd.sock" ] && break
	i=$((i + 1))
	sleep 0.2
done
[ -S "$HOME/.tyd/tyd.sock" ] || die "daemon did not create a socket: $(cat "$WORK/up.out")"
say "daemon up"

# ---- 3. loopback pairing ----------------------------------------------------

step "mint an invite"
LINE=$("$TYD_BINDIR/tyd" --platform "$PLATFORM" invite --no-wait 2>"$WORK/invite.err" | tr -d '\r' | grep -E 'accept ' | tail -1) ||
	die "invite produced no command: $(cat "$WORK/invite.err" 2>/dev/null)"
# `tyd invite` prints the command for the other side, and the installer prints
# one with --accept. Take the word after either.
TOKEN=$(printf '%s\n' "$LINE" | awk '{for (i = 1; i < NF; i++) if ($i == "accept" || $i == "--accept") { print $(i+1); exit }}')
[ -n "$TOKEN" ] || die "could not read the token from: $LINE"
say "token carries $(printf '%s' "$TOKEN" | awk -F. '{print NF}') parts (invite id, secret, inviter hash)"

step "accept it from a second identity"
CLIENT="$WORK/client"
mkdir -p "$CLIENT"
"$TYD_BINDIR/tyd" \
	--identity "$CLIENT/id_ed25519" \
	--trust "$CLIENT/trusted.json" \
	--peers "$CLIENT/peers.json" \
	--paired "$CLIENT/paired.json" \
	--platform "$PLATFORM" \
	accept "$TOKEN" >"$WORK/accept.out" 2>&1 ||
	die "accept failed: $(cat "$WORK/accept.out")"

PEER=$(tr -d '\r' <"$WORK/accept.out" | tail -1)
[ -n "$PEER" ] || die "accept printed no peer id"
say "paired with $PEER"

step "the server can see the pairing"
i=0
while [ "$i" -lt 60 ]; do
	# peer list prints one header line, then a row per peer.
	COUNT=$("$TYD_BINDIR/tyd" peer list 2>/dev/null | tail -n +2 | grep -c . || true)
	[ "${COUNT:-0}" -ge 1 ] && break
	i=$((i + 1))
	sleep 0.25
done
[ "${COUNT:-0}" -ge 1 ] || die "the server never saw the peer arrive (daemon log: $(tail -3 "$WORK/up.out" 2>/dev/null))"

step "the pairing is recorded on both sides"
[ -f "$HOME/.tyd/paired.json" ] || die "server wrote no pairing record"
[ -f "$CLIENT/paired.json" ] || die "client wrote no pairing record"
say "server and client both hold a pairing record"

# ---- 4. a session -----------------------------------------------------------

step "create a session and see it"
"$TYD_BINDIR/tyd" --platform "$PLATFORM" --data-listen 127.0.0.1:0 session create --detach >"$WORK/create.out" 2>"$WORK/create.err" ||
	die "session create failed: $(cat "$WORK/create.err" 2>/dev/null)$(cat "$WORK/create.out" 2>/dev/null)"
SID=$(tr -d '\r' <"$WORK/create.out" | tail -1)
[ -n "$SID" ] || die "session create printed no id"
"$TYD_BINDIR/tyd" --platform "$PLATFORM" session list 2>/dev/null | grep -q "$SID" ||
	die "session $SID is not in session list"
say "session $SID created and listed"

step "peer list shows the alias"
"$TYD_BINDIR/tyd" --platform "$PLATFORM" peer alias "$PEER" smoke >/dev/null 2>&1 ||
	die "peer alias failed"
"$TYD_BINDIR/tyd" --platform "$PLATFORM" session list 2>/dev/null | grep -q smoke ||
	die "session list does not show the peer nickname"

step "clean up the session"
"$TYD_BINDIR/tyd" --platform "$PLATFORM" session close "$SID" >/dev/null 2>&1 ||
	die "session close failed"

printf '\nsmoke: ok\n'
