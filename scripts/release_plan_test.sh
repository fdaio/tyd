#!/bin/sh
# Exercises scripts/release-plan.sh in a throwaway repo.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
plan="$root/scripts/release-plan.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
	echo "FAIL: $1" >&2
	echo "$2" >&2
	exit 1
}

field() {
	# $1 text, $2 key
	printf '%s\n' "$1" | awk -F= -v k="$2" '$1==k { print substr($0, length(k)+2); exit }'
}

newrepo() {
	rm -rf "$tmp/repo"
	mkdir -p "$tmp/repo"
	git -C "$tmp/repo" init -q
	git -C "$tmp/repo" config user.email "release-plan@example.com"
	git -C "$tmp/repo" config user.name "release-plan"
	git -C "$tmp/repo" config commit.gpgsign false
}

commit() {
	printf '%s\n' "$1" >"$tmp/repo/f"
	git -C "$tmp/repo" add f
	git -C "$tmp/repo" commit -q -m "$1"
}

runplan() {
	(cd "$tmp/repo" && RELEASE_DATE="$1" sh "$plan")
}

newrepo
commit one
short=$(git -C "$tmp/repo" rev-parse --short=7 HEAD)
out=$(runplan 2026.09.27)
got=$(field "$out" version)
[ "$got" = "2026.09.27-${short}" ] || fail "first version" "$out"
[ "$(field "$out" publish)" = true ] || fail "first publish" "$out"

git -C "$tmp/repo" tag v0.1.0
out=$(runplan 2026.09.27)
[ "$(field "$out" publish)" = true ] || fail "manual tag should not suppress" "$out"

git -C "$tmp/repo" tag "2026.09.27-${short}"
out=$(runplan 2026.09.28)
[ "$(field "$out" publish)" = false ] || fail "same commit next day should skip" "$out"
echo "$out" | grep -q "no new commits" || fail "skip reason" "$out"

commit two
short2=$(git -C "$tmp/repo" rev-parse --short=7 HEAD)
out=$(runplan 2026.09.28)
[ "$(field "$out" publish)" = true ] || fail "new commit publishes" "$out"
[ "$(field "$out" version)" = "2026.09.28-${short2}" ] || fail "second version" "$out"

git -C "$tmp/repo" tag "2026.09.28-${short2}"
out=$(runplan 2026.09.28)
[ "$(field "$out" publish)" = false ] || fail "repeat tag skips" "$out"

echo "release-plan ok"
