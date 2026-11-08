#!/bin/sh
# Exercises install.sh's checksum verifier without downloading a release.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC=$(mktemp -d /tmp/tyd-verify-src.XXXXXX)
WORK=$(mktemp -d /tmp/tyd-verify-work.XXXXXX)
trap 'rm -rf "$SRC" "$WORK"' EXIT INT TERM

awk '/^# verify_archive/{f=1} f{print} f&&/^}$/{exit}' "$ROOT/scripts/install.sh" >"$SRC/verify.sh"
[ -s "$SRC/verify.sh" ] || { echo "install-verify: verifier not found" >&2; exit 1; }

printf 'archive-data\n' >"$SRC/tyd-darwin-arm64.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
	sum="$(sha256sum "$SRC/tyd-darwin-arm64.tar.gz" | awk '{print $1}')"
else
	sum="$(shasum -a 256 "$SRC/tyd-darwin-arm64.tar.gz" | awk '{print $1}')"
fi
printf '%s  tyd-darwin-arm64.tar.gz\n' "$sum" >"$SRC/checksums.txt"

cat >"$SRC/run.sh" <<'SH'
set -eu
SRC="$1"
TMP="$2"
log() { :; }
die() { echo "die: $*" >&2; exit 1; }
curl() {
	dest=""
	url=""
	while [ $# -gt 0 ]; do
		case "$1" in
		-o) dest="$2"; shift 2 ;;
		-*) shift ;;
		*) url="$1"; shift ;;
		esac
	done
	cp "$SRC/${url##*/}" "$dest"
}
. "$SRC/verify.sh"
verify_archive "$SRC/tyd-darwin-arm64.tar.gz" "http://example/tyd-darwin-arm64.tar.gz"
SH

sh "$SRC/run.sh" "$SRC" "$WORK" >/dev/null

printf 'tampered\n' >"$SRC/tyd-darwin-arm64.tar.gz"
if (sh "$SRC/run.sh" "$SRC" "$WORK" >/dev/null 2>&1); then
	echo "install-verify: a mismatched archive was accepted" >&2
	exit 1
fi

echo "install-verify ok"
