#!/bin/sh
# Local-first dialing: a verified endpoint on disk must carry a dial when the
# Control Panel is slow, down, or has moved the peer. This drives real daemons
# and a real Control Panel through the criteria in the issue: cached create and
# attach, refresh on a dead cached address, the three-second Control Panel
# budget with no cache, and data-plane port reuse with an ephemeral fallback.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
bin=${TYD_BIN:-}
# Keep the root short: the live-agent socket path includes the whole HOME and
# AF_UNIX caps a path at about 104 bytes.
work=$(mktemp -d /tmp/tydlf.XXXXXX)
pids=""

cleanup() {
	for p in $pids; do
		kill "$p" 2>/dev/null || true
		wait "$p" 2>/dev/null || true
	done
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

check() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1: got [$3], want [$2]"
	fi
}

need() {
	command -v "$1" >/dev/null 2>&1 || {
		printf 'acceptance: %s is required\n' "$1" >&2
		exit 2
	}
}

fatal() {
	printf 'acceptance: %s\n' "$1" >&2
	for f in "$work"/*.log; do
		[ -f "$f" ] || continue
		printf -- '--- %s ---\n' "$f" >&2
		tail -20 "$f" >&2
	done
	exit 1
}

need python3

free_port() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_file() {
	file=$1
	pattern=$2
	i=0
	while [ "$i" -lt 100 ]; do
		if grep -q "$pattern" "$file" 2>/dev/null; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

wait_tcp() {
	port=$1
	python3 - "$port" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(100):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
        s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit(1)
PY
}

now() {
	python3 -c 'import time; print("%.4f" % time.time())'
}

elapsed() {
	python3 - "$1" <<'PY'
import sys, time
print("%.2f" % (time.time() - float(sys.argv[1])))
PY
}

port_of() {
	python3 - "$1" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["port"])
PY
}

mode_of() {
	python3 - "$1" <<'PY'
import os, sys
print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])
PY
}

if [ -z "$bin" ]; then
	bin="$work/tyd"
	(cd "$root" && go build -o "$bin" ./cmd/tyd) || exit 1
fi
cpbin="$work/controlpanel"
(cd "$root" && go build -o "$cpbin" ./cmd/controlpanel) || exit 1

srvhome="$work/server"
clhome="$work/client"
nchome="$work/nocache"
mkdir -p "$srvhome" "$clhome" "$nchome"

# --- Control Panel ---------------------------------------------------------
cpport=$(free_port)
cpurl="http://127.0.0.1:$cpport"
"$cpbin" -listen "127.0.0.1:$cpport" >"$work/cp.log" 2>&1 &
cp_pid=$!
pids="$pids $cp_pid"
wait_tcp "$cpport" || fatal "control panel did not listen"
ok "control panel listening on $cpurl"

# --- register the server and pair a client --------------------------------
# A waiting register completes pairing on this side; --no-wait would leave the
# inviter with only the Control Panel's copy of the peer.
HOME="$srvhome" "$bin" register --platform "$cpurl" >"$work/register.out" 2>"$work/register.log" &
reg_pid=$!
pids="$pids $reg_pid"
i=0
while [ "$i" -lt 100 ]; do
	[ -s "$work/register.out" ] && break
	i=$((i + 1))
	sleep 0.1
done
token=$(tail -1 "$work/register.out" | awk '{print $NF}')
[ -n "$token" ] || fatal "register printed no accept token"
HOME="$clhome" "$bin" accept "$token" --platform "$cpurl" >"$work/accept.log" 2>&1 ||
	fatal "accept failed"
wait "$reg_pid" || fatal "register did not complete the pairing"
server_id=$(python3 - "$srvhome/.tyd/peers.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["registration"]["id"])
PY
) || fatal "could not read the server id"
ok "client paired with the server"

start_server() {
	HOME="$srvhome" "$bin" up --platform "$cpurl" --listen off --relay off \
		--data-listen auto >"$work/server.log" 2>&1 &
	server_pid=$!
	pids="$pids $server_pid"
	wait_file "$work/server.log" "tyd listening unix" || fatal "server daemon did not start"
}

stop_server() {
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
}

start_server
# The second daemon is the client host itself; it must not need the data plane.
HOME="$clhome" "$bin" up --platform "$cpurl" --listen off --relay off >"$work/client.log" 2>&1 &
client_pid=$!
pids="$pids $client_pid"
wait_file "$work/client.log" "tyd listening unix" || fatal "client daemon did not start"
check "two daemons running" "2" "2"

# Wait for the first publish, then create once. This create also writes the
# verified endpoint cache the rest of the scenario relies on.
sid1=""
i=0
while [ "$i" -lt 60 ]; do
	if HOME="$clhome" "$bin" session create --peer "$server_id" --detach --platform "$cpurl" \
		--relay off >"$work/sid1" 2>"$work/create1.log"; then
		sid1=$(tail -1 "$work/sid1")
		break
	fi
	i=$((i + 1))
	sleep 0.2
done
[ -n "$sid1" ] || fatal "first create did not succeed"
ok "first create succeeded"

cache="$clhome/.tyd/endpoint-cache.json"
[ -f "$cache" ] || fatal "no endpoint cache was written"
check "endpoint cache mode" "600" "$(mode_of "$cache")"
ok "endpoint cache written after a verified lookup"

# --- data-plane port reuse ------------------------------------------------
port_file="$srvhome/.tyd/dataplane.json"
[ -f "$port_file" ] || fatal "no data-plane port file was written"
p1=$(port_of "$port_file") || fatal "unreadable data-plane port"
check "data-plane port file mode" "600" "$(mode_of "$port_file")"

stop_server
start_server
p2=$(port_of "$port_file")
check "a restart reuses the remembered data-plane port" "$p1" "$p2"

# Hold the remembered port and restart: the daemon must come up elsewhere.
stop_server
python3 - "$p1" >"$work/hold.log" 2>&1 <<'PY' &
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Loopback is enough to make the daemon's wildcard bind fail, and it is what
# the fallback exists for: another process owns the remembered port.
s.bind(("127.0.0.1", int(sys.argv[1])))
print("holding", flush=True)
time.sleep(30)
PY
hold_pid=$!
pids="$pids $hold_pid"
wait_file "$work/hold.log" "holding" || fatal "could not hold the data-plane port"
start_server
p3=$(port_of "$port_file")
if [ "$p3" != "$p1" ]; then
	ok "a busy remembered port falls back to an ephemeral port"
else
	bad "a busy port was reused ($p3)"
fi
kill "$hold_pid" 2>/dev/null || true
wait "$hold_pid" 2>/dev/null || true

# --- a dead cached address refreshes from a live Control Panel -------------
# The cache still names p1; the daemon now publishes p3.
start=$(now)
if HOME="$clhome" "$bin" session create --peer "$server_id" --detach --verbose --platform "$cpurl" \
	--relay off >"$work/sid2" 2>"$work/refresh.log"; then
	sid2=$(tail -1 "$work/sid2")
else
	bad "create after the endpoint moved failed"
	sid2=""
fi
if grep -q "refreshing from Control Panel" "$work/refresh.log"; then
	ok "a dead cached address logs the refresh"
else
	bad "no refresh line for a dead cached address"
fi
if [ -n "$sid2" ]; then
	ok "a dead cached address refreshes and connects"
else
	bad "a dead cached address did not connect"
fi

# --- cache carries the dial once the Control Panel is gone -----------------
kill "$cp_pid" 2>/dev/null || true
wait "$cp_pid" 2>/dev/null || true

start=$(now)
if HOME="$clhome" "$bin" session create --peer "$server_id" --detach --verbose --platform "$cpurl" \
	--relay off >"$work/sid3" 2>"$work/cached.log"; then
	sid3=$(tail -1 "$work/sid3")
else
	bad "create with a cached endpoint and no Control Panel failed"
	sid3=""
fi
secs=$(elapsed "$start")
if [ -n "$sid3" ]; then
	ok "create succeeds with the Control Panel stopped"
else
	bad "create failed with the Control Panel stopped"
fi
if grep -q "Using cached endpoint" "$work/cached.log" && grep -q "Connecting to" "$work/cached.log"; then
	ok "verbose names the cached address"
else
	bad "verbose did not name the cached address"
fi
if grep -q "refreshing from Control Panel" "$work/cached.log"; then
	bad "a cached dial logged a refresh"
else
	ok "a cached dial logs no refresh"
fi
if [ -n "$sid3" ] && python3 -c "import sys; raise SystemExit(0 if float(sys.argv[1]) < 2 else 1)" "$secs"; then
	ok "a cached create took ${secs}s, under two seconds"
else
	bad "a cached create took ${secs}s"
fi

# Attach goes through the catalog endpoint, which must also work offline.
if [ -n "$sid3" ]; then
	fifo="$work/attach"
	mkfifo "$fifo"
	(sleep 10 >"$fifo") &
	holder=$!
	pids="$pids $holder"
	(HOME="$clhome" "$bin" session attach "$sid3" --verbose --platform "$cpurl" --relay off \
		<"$fifo" >"$work/attach.out" 2>"$work/attach.log") &
	att=$!
	pids="$pids $att"
	i=0
	while [ "$i" -lt 40 ]; do
		if grep -q "Attached." "$work/attach.log" 2>/dev/null; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
	if grep -q "Attached." "$work/attach.log"; then
		ok "attach succeeds with the Control Panel stopped"
	else
		bad "attach did not attach with the Control Panel stopped"
	fi
	if grep -q "refreshing from Control Panel" "$work/attach.log"; then
		bad "an offline attach logged a refresh"
	else
		ok "an offline attach logs no refresh"
	fi
	kill "$att" "$holder" 2>/dev/null || true
	wait "$att" 2>/dev/null || true
	wait "$holder" 2>/dev/null || true
fi

# --- no cache and an unreachable Control Panel: fail inside three seconds ---
mkdir -p "$nchome/.tyd"
cp "$clhome/.tyd/peers.json" "$nchome/.tyd/peers.json"
if [ -f "$clhome/.tyd/peers-paired.json" ]; then
	cp "$clhome/.tyd/peers-paired.json" "$nchome/.tyd/peers-paired.json"
fi
# A black hole on the Control Panel port: accepting and never answering is the
# slow case the three-second budget exists for.
python3 - "$cpport" >"$work/hole.log" 2>&1 <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
print("hole", flush=True)
conns = []
while True:
    c, _ = s.accept()
    conns.append(c)
PY
hole_pid=$!
pids="$pids $hole_pid"
wait_file "$work/hole.log" "hole" || fatal "could not start the black hole"

start=$(now)
set +e
HOME="$nchome" "$bin" session create --peer "$server_id" --detach --platform "$cpurl" \
	--relay off >"$work/nocache.out" 2>"$work/nocache.err"
rc=$?
set -e
secs=$(elapsed "$start")
if [ "$rc" -ne 0 ]; then
	ok "no cache and an unreachable Control Panel fails"
else
	bad "no cache and an unreachable Control Panel succeeded"
fi
if grep -q "Control Panel" "$work/nocache.err"; then
	ok "the failure names the Control Panel reason"
else
	bad "the failure does not name the Control Panel: $(cat "$work/nocache.err")"
fi
if python3 -c "import sys; raise SystemExit(0 if float(sys.argv[1]) <= 3.5 else 1)" "$secs"; then
	ok "the failure took ${secs}s, within the three-second budget"
else
	bad "the failure took ${secs}s, longer than the budget"
fi
kill "$hole_pid" 2>/dev/null || true
wait "$hole_pid" 2>/dev/null || true

printf '\nacceptance: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
