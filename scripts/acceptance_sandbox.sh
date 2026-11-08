#!/bin/sh
# Drives a real sandboxed session through the CLI: create, send, read, close.
#
# The runtime and image must already be present. Set TYD_SANDBOX_BACKEND,
# TYD_SANDBOX_IMAGE, and TYD_SANDBOX_WORKDIR to override the defaults.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/tyd"
BACKEND="${TYD_SANDBOX_BACKEND:-docker}"
IMAGE="${TYD_SANDBOX_IMAGE:-debian:bookworm}"

if ! command -v "$BACKEND" >/dev/null 2>&1; then
  echo "acceptance-sandbox: $BACKEND not found; skip" >&2
  exit 0
fi
if ! "$BACKEND" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "acceptance-sandbox: image $IMAGE is not local; pull it first" >&2
  exit 1
fi

WORK=$(mktemp -d "${TYD_SANDBOX_WORKDIR:-/tmp}/tyd-sandbox-work.XXXXXX")
HOME_DIR=$(mktemp -d /tmp/tyd-sandbox-home.XXXXXX)
trap 'rm -rf "$WORK" "$HOME_DIR"' EXIT INT TERM

export HOME="$HOME_DIR"
"$BIN" up --sandbox "$BACKEND" --sandbox-image "$IMAGE" \
  --sandbox-workdir "$WORK" --sandbox-network none >"$HOME_DIR/up.log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$WORK" "$HOME_DIR"' EXIT INT TERM

i=0
while [ ! -S "$HOME_DIR/.tyd/tyd.sock" ]; do
  i=$((i + 1))
  [ "$i" -lt 150 ] || { echo "acceptance-sandbox: daemon did not start" >&2; cat "$HOME_DIR/up.log"; exit 1; }
  sleep 0.2
done

SID=$("$BIN" session create --detach)
"$BIN" session send "$SID" "pwd; id -u; test -f $HOME/.tyd/id_ed25519 && echo HOST_KEY_VISIBLE || echo HOST_KEY_HIDDEN; echo SANDBOX_OK
"
OUT=""
i=0
while [ "$i" -lt 15 ]; do
  OUT=$("$BIN" session read "$SID" --wait 2s)
  if printf '%s\n' "$OUT" | tr -d '\r' | grep -qx SANDBOX_OK; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
"$BIN" session close "$SID"

fail=0
for want in "$WORK" "$(id -u)" HOST_KEY_HIDDEN SANDBOX_OK; do
  if ! printf '%s\n' "$OUT" | tr -d '\r' | grep -qx "$want"; then
    echo "acceptance-sandbox: output missing $want" >&2
    fail=1
  fi
done
if printf '%s\n' "$OUT" | tr -d '\r' | grep -qx HOST_KEY_VISIBLE; then
  echo "acceptance-sandbox: the daemon state is visible inside the container" >&2
  fail=1
fi
if [ "$fail" -ne 0 ]; then
  printf '%s\n' "$OUT" >&2
  exit 1
fi
echo "acceptance-sandbox: ok ($BACKEND $IMAGE)"
