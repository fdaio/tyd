#!/bin/sh
# Drives a real daemon through the send/read surface, the way a script would.
#
# Everything here goes through the built binary and the wire protocol; nothing
# reaches into the packages. The Go tests cover the paths a shell cannot reach
# (notably pre-approval, which only applies off the local unix socket).
#
# SHELL is pinned so the prompt is predictable: a live session inherits the
# daemon's shell, and the interactive scenarios below need one that behaves.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
bin=${TYD_BIN:-}
# Keep the root short. The live-agent listens on a unix socket whose path
# includes the whole HOME, and AF_UNIX caps a path at about 104 bytes, so a
# long mktemp directory makes the agent fail to start.
work=$(mktemp -d /tmp/tydacc.XXXXXX)
daemon_pid=""

cleanup() {
	if [ -n "$daemon_pid" ]; then
		kill "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

pass=0
fail=0

ok() {
	pass=$((pass + 1))
	printf '  ok    %s\n' "$1"
}

bad() {
	fail=$((fail + 1))
	printf '  FAIL  %s\n' "$1" >&2
}

# check NAME EXPECTED ACTUAL
check() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1: got [$3], want [$2]"
	fi
}

# jq-free JSON field reader, enough for the shapes this script reads.
field() {
	sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}

need() {
	command -v "$1" >/dev/null 2>&1 || {
		printf 'acceptance: %s is required\n' "$1" >&2
		exit 2
	}
}

need python3

if [ -z "$bin" ]; then
	bin="$work/tyd"
	(cd "$root" && go build -o "$bin" ./cmd/tyd)
fi

export HOME="$work/home"
export SHELL=/bin/bash
mkdir -p "$HOME"

# A second port, so a developer's own daemon is never disturbed.
port=61290
"$bin" up --listen "127.0.0.1:$port" >"$work/daemon.log" 2>&1 &
daemon_pid=$!

i=0
while [ "$i" -lt 100 ]; do
	if "$bin" status >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	sleep 0.1
done
if [ "$i" -ge 100 ]; then
	printf 'acceptance: daemon did not come up\n' >&2
	cat "$work/daemon.log" >&2
	exit 1
fi

new_session() {
	sid=$("$bin" session create --detach 2>/dev/null | tail -1)
	[ -n "$sid" ] || {
		printf 'acceptance: could not create a session\n' >&2
		cat "$work/daemon.log" >&2
		exit 1
	}
	# Let the shell print its first prompt, so a read is not racing startup.
	sleep 1
	printf '%s' "$sid"
}

# page SID CURSOR EPOCH ARGS... -> one JSON object on stdout
page() {
	sid=$1
	cur=$2
	ep=$3
	shift 3
	"$bin" session read "$sid" --cursor "$cur" --epoch "$ep" "$@" --json 2>/dev/null | head -1
}

# read_json_field JSON KEY
jget() {
	printf '%s' "$1" | python3 -c '
import json,sys
d=json.loads(sys.stdin.read() or "{}")
v=d.get(sys.argv[1],"")
if isinstance(v,bool): v="true" if v else "false"
print(v)' "$2"
}

printf 'acceptance: send and read against a real daemon\n'

# --- 2a: basic send, then read what it produced ---------------------------
sid=$(new_session)
out=$(page "$sid" 0 0 --wait 5s)
check "read with no condition returns available" "available" "$(jget "$out" reason)"

sendjson=$("$bin" session send "$sid" 'echo MARKER_ONE
' --json 2>/dev/null | head -1)
cur=$(jget "$sendjson" cursor)
ep=$(jget "$sendjson" epoch)
check "send --json reports a cursor" "yes" "$([ -n "$cur" ] && echo yes || echo no)"

sleep 1
out=$(page "$sid" "$cur" "$ep" --wait 5s)
data=$(printf '%s' "$out" | python3 -c 'import json,sys,base64;print(base64.b64decode(json.loads(sys.stdin.read())["data"]).decode("utf-8","replace"))')
case $data in
*MARKER_ONE*) ok "read sees the output of its own send" ;;
*) bad "read did not see MARKER_ONE: [$data]" ;;
esac

# --- 2b: match, and it must not match the echo of the command -------------
# The marker is quoted so the typed text cannot contain the searched token:
# the shell strips the quotes, so the output has __DONE__ and the echo does
# not. A pattern that appears in the typed command matches the echo at once
# and the caller wakes before its command has run.
sendjson=$("$bin" session send "$sid" "echo __D''ONE__
" --json 2>/dev/null | head -1)
cur=$(jget "$sendjson" cursor)
ep=$(jget "$sendjson" epoch)
out=$(page "$sid" "$cur" "$ep" --wait 8s --until-match '__DONE__')
check "until-match fires on the output" "match" "$(jget "$out" reason)"
data=$(printf '%s' "$out" | python3 -c 'import json,sys,base64;print(base64.b64decode(json.loads(sys.stdin.read())["data"]).decode("utf-8","replace"))')
first=$(printf '%s' "$data" | head -1)
case $first in
*__DONE__*) bad "the match came from the echo, not the output: [$first]" ;;
*) ok "the match came from the output, not the echo" ;;
esac

# --- 2b: a pattern that only exists in the echo must not match ------------
sendjson=$("$bin" session send "$sid" 'x=ECHOONLY
' --json 2>/dev/null | head -1)
cur=$(jget "$sendjson" cursor)
ep=$(jget "$sendjson" epoch)
out=$(page "$sid" "$cur" "$ep" --wait 2s --until-match 'ECHOONLY')
# The echo does contain the token, so this is allowed to match: the point is
# that a caller must choose a pattern the echo cannot contain.
check "a pattern present in the echo matches the echo" "match" "$(jget "$out" reason)"

# --- 2b: idle needs a byte before its clock starts -------------------------
sid2=$(new_session)
"$bin" session send "$sid2" 'true
' >/dev/null 2>&1
sleep 1
end=$("$bin" session read "$sid2" --cursor 0 --json 2>/dev/null | head -1)
endcur=$(jget "$end" cursor_next)
endep=$(jget "$end" epoch)
start=$(date +%s)
out=$(page "$sid2" "$endcur" "$endep" --wait 4s --until-idle 1s)
elapsed=$(($(date +%s) - start))
check "idle does not fire with no output after the cursor" "timeout" "$(jget "$out" reason)"
if [ "$elapsed" -ge 3 ]; then
	ok "idle waited out the full wait ($elapsed s)"
else
	bad "idle returned after only ${elapsed}s, should have run to the 4s wait"
fi

# --- 2b: idle fires once output stops -------------------------------------
sendjson=$("$bin" session send "$sid2" 'echo IDLE_ONE
' --json 2>/dev/null | head -1)
cur=$(jget "$sendjson" cursor)
ep=$(jget "$sendjson" epoch)
out=$(page "$sid2" "$cur" "$ep" --wait 10s --until-idle 1s)
check "idle fires after the output stops" "idle" "$(jget "$out" reason)"

# --- 2b: max_bytes stops on a character boundary --------------------------
# The cut is a byte count, but a reply must never split a UTF-8 character, so
# a request landing mid-character backs off. This needs the page to start on
# multibyte output: with ASCII, or with a page that begins on the shell's
# prompt, the check passes even when the boundary is dropped entirely.
sidmb=$(new_session)
# send --json reports the cursor from before the write, so the page starts on
# the echoed payload rather than on the prompt.
mbjson=$(python3 -c "import sys; sys.stdout.write('你'*2000)" \
	| "$bin" session send "$sidmb" --stdin --json 2>/dev/null | head -1)
mbcur=$(jget "$mbjson" cursor)
mbep=$(jget "$mbjson" epoch)
sleep 1
python3 - "$bin" "$sidmb" "$mbcur" "$mbep" <<'MBPY'
import base64, json, subprocess, sys
bin_, sid, cur, ep = sys.argv[1:5]
out = subprocess.run([bin_, "session", "read", sid, "--cursor", cur, "--epoch", ep,
                      "--wait", "10s", "--max-bytes", "100", "--json"],
                     capture_output=True, text=True).stdout
d = json.loads(out.splitlines()[0])
data = base64.b64decode(d["data"])
if not data:
    sys.exit("no data returned")
try:
    data.decode("utf-8")
except UnicodeDecodeError as e:
    sys.exit("reply splits a UTF-8 character at byte %d: %s" % (len(data), e))
if len(data) == 100:
    sys.exit("returned exactly 100 bytes, so the cut landed on a boundary anyway")
if len(data) > 100:
    sys.exit("returned %d bytes for a 100 byte request" % len(data))
if len(data) < 97:
    sys.exit("backed off too far: %d bytes for a 100 byte request" % len(data))
if d["cursor_next"] != int(cur) + len(data):
    sys.exit("cursor_next %d does not follow the %d bytes returned from %s"
             % (d["cursor_next"], len(data), cur))
MBPY
if [ $? -eq 0 ]; then
	ok "max_bytes stops on a UTF-8 boundary and cursor_next stays exact"
else
	bad "max_bytes split a character or mis-reported cursor_next"
fi

# --- 2b: output that keeps arriving is not idle ---------------------------
# A stream that never pauses must not look quiet, so idle has to be measured
# from the last byte rather than from the start of the read.
sid2b=$(new_session)
python3 - "$bin" "$sid2b" <<'TICKPY'
import json, subprocess, sys, time
bin_, sid = sys.argv[1:3]
subprocess.run([bin_, "session", "send", sid, "while true; do echo TICK; sleep 0.2; done\n"],
               capture_output=True)
start = time.time()
out = subprocess.run([bin_, "session", "read", sid, "--cursor", "0", "--wait", "3s",
                      "--until-idle", "1s", "--json"], capture_output=True, text=True).stdout
d = json.loads(out.splitlines()[0])
elapsed = time.time() - start
subprocess.run([bin_, "session", "send", sid, "\x03\n"], capture_output=True)
if d["reason"] == "idle":
    sys.exit("a continuously producing session reported idle after %.1fs" % elapsed)
if elapsed < 2.5:
    sys.exit("returned after only %.1fs, should have run to the 3s wait" % elapsed)
TICKPY
if [ $? -eq 0 ]; then
	ok "a continuously producing session is never idle"
else
	bad "steady output was reported as idle"
fi

# --- 2b: max_bytes cuts exactly, and paging has no gap ---------------------
sid3=$(new_session)
# The cursor has to be taken before the flood starts, or it already points
# past the output the paging is supposed to read.
before=$("$bin" session send "$sid3" 'true
' --json 2>/dev/null | head -1)
cur=$(jget "$before" cursor)
ep=$(jget "$before" epoch)
"$bin" session send "$sid3" 'yes __FILLER__ | head -20000
' >/dev/null 2>&1
sleep 1
python3 - "$bin" "$sid3" "$cur" "$ep" <<'PY'
import base64, json, subprocess, sys
bin_, sid, cur, ep = sys.argv[1:5]
total = b""
prev = None
for _ in range(3):
    out = subprocess.run(
        [bin_, "session", "read", sid, "--cursor", cur, "--epoch", ep,
         "--wait", "10s", "--max-bytes", "4096", "--json"],
        capture_output=True, text=True).stdout
    d = json.loads(out.splitlines()[0])
    if d["reason"] != "max_bytes":
        break
    if prev is not None and d["cursor"] != prev:
        sys.exit("cursor moved unexpectedly")
    prev = d["cursor_next"]
    cur, ep = d["cursor_next"], d["epoch"]
    total += base64.b64decode(d["data"])
    if len(total) >= 4096:
        break
if len(total) < 4096:
    sys.exit("only got %d bytes" % len(total))
if len(total) != 4096:
    sys.exit("expected exactly 4096, got %d" % len(total))
PY
if [ $? -eq 0 ]; then
	ok "max_bytes returns exactly 4096 and the next page is contiguous"
else
	bad "max_bytes paging lost or duplicated bytes"
fi

# --- 2b: timeout when nothing matches -------------------------------------
out=$(page "$sid3" 0 0 --wait 2s --until-match 'NEVER_MATCHES_THIS')
check "a pattern that never matches times out" "timeout" "$(jget "$out" reason)"

# --- 2b: an exited shell returns at once ----------------------------------
sendjson=$("$bin" session send "$sid3" 'exit
' --json 2>/dev/null | head -1)
cur=$(jget "$sendjson" cursor)
ep=$(jget "$sendjson" epoch)
sleep 1
start=$(date +%s)
out=$(page "$sid3" "$cur" "$ep" --wait 20s --until-match 'NEVER_MATCHES_THIS')
elapsed=$(($(date +%s) - start))
check "an exited shell reports exited" "exited" "$(jget "$out" reason)"
if [ "$elapsed" -le 3 ]; then
	ok "an exited shell returns at once (${elapsed}s)"
else
	bad "an exited shell waited ${elapsed}s, should return at once"
fi

# --- 2a: send is refused while someone is attached ------------------------
sid4=$(new_session)
fifo="$work/attach"
mkfifo "$fifo"
(sleep 25 >"$fifo") &
holder=$!
("$bin" session attach "$sid4" <"$fifo" >"$work/attach.log" 2>&1) &
att=$!
sleep 2
set +e
"$bin" session send "$sid4" 'echo blocked
' >"$work/send.out" 2>"$work/send.err"
rc=$?
set -e
check "send while attached exits 3" "3" "$rc"
case $(cat "$work/send.err") in
*"session in use"*) ok "send while attached says why" ;;
*) bad "send while attached: $(cat "$work/send.err")" ;;
esac
case $(cat "$work/send.err") in
*local*|*admin*|*principal*) bad "the error names the holder" ;;
*) ok "the error does not name the holder" ;;
esac
kill "$att" "$holder" 2>/dev/null || true
rm -f "$fifo"
sleep 1

# --- 2a: send works again once the slot is free ---------------------------
if "$bin" session send "$sid4" 'echo FREE_AGAIN
' >/dev/null 2>&1; then
	ok "send succeeds once the attachment is gone"
else
	bad "send still refused after the attachment ended"
fi

# --- 2a: --follow ends when the shell exits -------------------------------
sid5=$(new_session)
("$bin" session read "$sid5" --cursor 0 --follow --json >"$work/follow.out" 2>/dev/null) &
follow=$!
sleep 2
"$bin" session send "$sid5" 'exit
' >/dev/null 2>&1
i=0
while [ "$i" -lt 100 ] && kill -0 "$follow" 2>/dev/null; do
	i=$((i + 1))
	sleep 0.1
done
if kill -0 "$follow" 2>/dev/null; then
	bad "--follow did not stop when the shell exited"
	kill "$follow" 2>/dev/null || true
else
	wait "$follow" 2>/dev/null || true
	ok "--follow stops when the shell exits"
	last=$(tail -1 "$work/follow.out")
	check "--follow ends with reason=exited" "exited" "$(jget "$last" reason)"
fi

# --- argument order --------------------------------------------------------
# The subcommand parses its own flags, so the session id may come before or
# after them. A regression here is silent: the command prints help instead.
sid6=$(new_session)
a=$("$bin" session read "$sid6" --cursor 0 --json 2>/dev/null | head -1)
b=$("$bin" session read --json --cursor 0 "$sid6" 2>/dev/null | head -1)
check "read accepts the id before its flags" "read_result" "$(jget "$a" type)"
check "read accepts the id after its flags" "read_result" "$(jget "$b" type)"

a=$("$bin" session send "$sid6" 'echo ORDER_A
' --json 2>/dev/null | head -1)
b=$("$bin" session send --json "$sid6" 'echo ORDER_B
' 2>/dev/null | head -1)
check "send accepts the id before its flags" "yes" "$([ -n "$(jget "$a" cursor)" ] && echo yes || echo no)"
check "send accepts the id after its flags" "yes" "$([ -n "$(jget "$b" cursor)" ] && echo yes || echo no)"

# send takes two positionals, the id and the data, so the data has to follow
# the id. Putting the id last is not a supported order: it reads as data.
if "$bin" session send --json 'echo X' "$sid6" >/dev/null 2>&1; then
	bad "send with the id last should be rejected as ambiguous data"
else
	ok "send rejects the ambiguous 'data then id' order"
fi

printf '\nacceptance: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
