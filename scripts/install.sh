#!/bin/sh
# tyd one-click install: GitHub Release binary + pairing bootstrap.
# Human (TTY): choose server or client; server can mint a copy-paste client command.
# Agent / non-TTY: --agent (default server) or --client --accept TOKEN.
#
# Everything installs for the invoking user: no sudo, no system-wide service.
# tyd holds that user's shells, so it never needs more privilege than the user has.
set -eu

INSTALL_URL="${TYD_INSTALL_URL:-}"
PLATFORM_URL="${TYD_PLATFORM:-}"
RELEASE_URL="${TYD_RELEASE_URL:-}"
ROLE=""
ACCEPT_TOKEN=""
AGENT=0
AS_NAME=""
SERVICE_ONLY=0

usage() {
	cat <<'EOF'
Install tyd from the latest GitHub Release.

Usage:
  curl -fsSL https://app.getfda.dev/install.sh | sh
  curl -fsSL ... | sh -s -- --agent
  curl -fsSL ... | sh -s -- --client --accept TOKEN

Options:
  --server            Install as server (this machine holds sessions)
  --client            Install as client (no daemon)
  --service           Start the user daemon for an already installed binary
  --agent             Non-interactive server; print client bootstrap and exit
  --accept TOKEN      Invite token (client)
  --as NAME           Peer nickname when accepting
  --platform URL      Control Panel URL
  -h, --help          Show this help

Env: TYD_INSTALL_URL, TYD_PLATFORM, TYD_RELEASE_URL, TYD_BINDIR

Installs for the current user only (~/.local/bin, systemd --user or launchd).
Do not run this with sudo.

Binaries are fetched from GitHub Releases:
  https://github.com/fdaio/tyd/releases/latest/download/tyd-<os>-<arch>.tar.gz
Override with TYD_RELEASE_URL. --platform only changes the Control Panel.
EOF
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'tyd install: %s\n' "$*" >&2; exit 1; }

have_tty() {
	[ -r /dev/tty ] && [ -w /dev/tty ]
}

prompt() {
	def="$2"
	if ! have_tty; then
		printf '%s\n' "$def"
		return
	fi
	printf '%s ' "$1" >/dev/tty
	ans=""
	IFS= read -r ans </dev/tty || true
	[ -n "$ans" ] || ans="$def"
	printf '%s\n' "$ans"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--server) ROLE=server ;;
	--client) ROLE=client ;;
	--service)
		SERVICE_ONLY=1
		ROLE=server
		;;
	--agent)
		AGENT=1
		[ -n "$ROLE" ] || ROLE=server
		;;
	--accept)
		[ $# -ge 2 ] || die "--accept needs a token"
		ACCEPT_TOKEN="$2"
		shift
		;;
	--as)
		[ $# -ge 2 ] || die "--as needs a name"
		AS_NAME="$2"
		shift
		;;
	--platform)
		[ $# -ge 2 ] || die "--platform needs a URL"
		PLATFORM_URL="$2"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "unknown option: $1"
		;;
	esac
	shift
done

if [ -z "$INSTALL_URL" ]; then
	base="https://app.getfda.dev"
	if [ -n "$PLATFORM_URL" ]; then
		base="${PLATFORM_URL%/}"
	fi
	INSTALL_URL="${base}/install.sh"
else
	base="${INSTALL_URL%/install.sh}"
	base="${base%/}"
	if [ -n "$PLATFORM_URL" ]; then
		base="${PLATFORM_URL%/}"
	fi
fi
if [ -z "$PLATFORM_URL" ]; then
	PLATFORM_URL="$base"
fi

if [ "$AGENT" -eq 1 ] && [ -z "$ROLE" ]; then
	ROLE=server
fi
if [ -z "$ROLE" ]; then
	if have_tty && [ -z "$ACCEPT_TOKEN" ]; then
		log "Install tyd as:"
		log "  1) server  (this machine holds sessions; run the daemon)"
		log "  2) client  (connect to a server; needs an invite token)"
		choice="$(prompt 'Choose 1 or 2 [1]:' '1')"
		case "$choice" in
		2 | c | C | client | Client) ROLE=client ;;
		*) ROLE=server ;;
		esac
	elif [ -n "$ACCEPT_TOKEN" ]; then
		ROLE=client
	else
		ROLE=server
		AGENT=1
	fi
fi

if [ "$ROLE" = client ] && [ -z "$ACCEPT_TOKEN" ]; then
	if have_tty; then
		ACCEPT_TOKEN="$(prompt 'Invite token (from the server):' '')"
	fi
	[ -n "$ACCEPT_TOKEN" ] || die "client install needs --accept TOKEN"
fi

detect_os() {
	u="$(uname -s | tr '[:upper:]' '[:lower:]')"
	case "$u" in
	linux | darwin | freebsd) printf '%s\n' "$u" ;;
	*) die "unsupported OS: $u (need linux, darwin, or freebsd)" ;;
	esac
}

detect_arch() {
	m="$(uname -m)"
	case "$m" in
	x86_64 | amd64) printf 'amd64\n' ;;
	aarch64 | arm64) printf 'arm64\n' ;;
	*) die "unsupported arch: $m (need amd64 or arm64)" ;;
	esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

HOME_DIR="${HOME:-/tmp}"
if [ -n "${TYD_BINDIR:-}" ]; then
	BINDIR="$TYD_BINDIR"
else
	BINDIR="${HOME_DIR}/.local/bin"
fi

TYD_DIR="${HOME_DIR}/.tyd"
mkdir -p "$BINDIR" "$TYD_DIR"

is_root() {
	[ "$(id -u)" -eq 0 ]
}

if is_root; then
	log "note: running as root. tyd installs per-user and needs no sudo;"
	log "      this puts tyd and its sessions under $(id -un) ($HOME_DIR)."
fi

# Replace via temp + mv so a running tyd (ETXTBSY) does not block upgrade.
# The old process keeps the previous inode; new invocations use the new file.
install_binary() {
	src="$1"
	dest="$2"
	dir="$(dirname "$dest")"
	mkdir -p "$dir"
	tmp="${dest}.new.$$"
	cp "$src" "$tmp"
	chmod 755 "$tmp"
	if ! mv -f "$tmp" "$dest"; then
		rm -f "$tmp"
		die "could not install binary to $dest"
	fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT HUP

if [ "$SERVICE_ONLY" -eq 1 ]; then
	TYD="${BINDIR}/tyd"
	[ -x "$TYD" ] || die "no binary at $TYD"
	log "Using installed binary $TYD"
else
	log "Installing tyd (${OS}/${ARCH}) to ${BINDIR}/tyd"
	ARCHIVE="$TMP/tyd.tgz"
	if [ -z "$RELEASE_URL" ]; then
		RELEASE_URL="https://github.com/fdaio/tyd/releases/latest/download/tyd-${OS}-${ARCH}.tar.gz"
	fi
	URL="$RELEASE_URL"
	if ! curl -fsSL --retry 3 -o "$ARCHIVE" "$URL"; then
		die "download failed: $URL (GitHub Release asset tyd-${OS}-${ARCH}.tar.gz, or set TYD_RELEASE_URL, or build with make build)"
	fi
	tar -xzf "$ARCHIVE" -C "$TMP"
	SRC="$TMP/tyd"
	[ -f "$SRC" ] || die "archive missing tyd (expected a tyd-<os>-<arch>.tar.gz built by make dist)"
	install_binary "$SRC" "${BINDIR}/tyd"
	TYD="${BINDIR}/tyd"
fi

[ -x "$TYD" ] || die "binary not executable: $TYD"

extract_token() {
	line="$(printf '%s\n' "$1" | tr -d '\r' | grep -E 'accept ' | tail -n 1 || true)"
	[ -n "$line" ] || line="$(printf '%s\n' "$1" | tr -d '\r' | tail -n 1)"
	tok=""
	prev=""
	for w in $line; do
		if [ "$prev" = accept ]; then
			tok="$w"
			break
		fi
		prev="$w"
	done
	printf '%s\n' "$tok"
}

print_client_bootstrap() {
	tok="$1"
	[ -n "$tok" ] || die "empty invite token"
	extra=""
	if [ -n "$PLATFORM_URL" ]; then
		extra=" --platform ${PLATFORM_URL}"
	fi
	cmd="curl -fsSL ${INSTALL_URL} | sh -s -- --client${extra} --accept ${tok}"
	log ""
	log "On the client machine, run:"
	log ""
	log "  $cmd"
	log ""
	printf '%s\n' "$cmd"
}

has_systemd_user() {
	command -v systemctl >/dev/null 2>&1 || return 1
	systemctl --user show-environment >/dev/null 2>&1
}

start_daemon_systemd_user() {
	unit_dir="${HOME_DIR}/.config/systemd/user"
	mkdir -p "$unit_dir"
	cat >"${unit_dir}/tyd.service" <<UNIT
[Unit]
Description=tyd session daemon
After=network-online.target

[Service]
ExecStart=${TYD} up
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
	# Linger first, so the user manager (and this service) survive SSH logout.
	loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || log "warning: could not enable linger; the daemon may stop at logout"
	systemctl --user daemon-reload
	systemctl --user enable --now tyd.service
	log "Started tyd via systemd --user (tyd.service)"
}

start_daemon_launchd() {
	plist="${HOME_DIR}/Library/LaunchAgents/dev.getfda.tyd.plist"
	mkdir -p "$(dirname "$plist")"
	cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.getfda.tyd</string>
  <key>ProgramArguments</key>
  <array>
    <string>${TYD}</string>
    <string>up</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${TYD_DIR}/tyd.log</string>
  <key>StandardErrorPath</key>
  <string>${TYD_DIR}/tyd.log</string>
</dict>
</plist>
PLIST
	launchctl unload "$plist" >/dev/null 2>&1 || true
	launchctl load -w "$plist"
	log "Started tyd via launchd (dev.getfda.tyd)"
}

start_daemon_nohup() {
	# Caller (restart_daemon / fresh install) must ensure no live daemon remains.
	if [ -S "${TYD_DIR}/tyd.sock" ]; then
		log "removing stale socket ${TYD_DIR}/tyd.sock"
		rm -f "${TYD_DIR}/tyd.sock"
	fi
	# setsid leaves the installing shell and an SSH session. A foreground
	# `tyd up` dies on logout; this path must not.
	if command -v setsid >/dev/null 2>&1; then
		setsid "$TYD" up >>"${TYD_DIR}/tyd.log" 2>&1 </dev/null &
	else
		nohup "$TYD" up >>"${TYD_DIR}/tyd.log" 2>&1 </dev/null &
	fi
	printf '%s\n' "$!" >"${TYD_DIR}/tyd.pid"
	log "Started tyd (pid $(cat "${TYD_DIR}/tyd.pid"), log ${TYD_DIR}/tyd.log)"
}

start_daemon() {
	case "$OS" in
	linux)
		if has_systemd_user; then
			start_daemon_systemd_user
		else
			start_daemon_nohup
		fi
		;;
	darwin)
		# A LaunchAgent under /var/root is never loaded, so root gets nohup.
		if is_root; then
			log "root on macOS has no login session for launchd; using nohup"
			log "install as your own user to get a LaunchAgent that survives logout"
			start_daemon_nohup
		else
			start_daemon_launchd
		fi
		;;
	*)
		start_daemon_nohup
		;;
	esac
	i=0
	while [ "$i" -lt 20 ]; do
		if [ -S "${TYD_DIR}/tyd.sock" ]; then
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	log "error: daemon did not create ${TYD_DIR}/tyd.sock; check ${TYD_DIR}/tyd.log"
	return 1
}

daemon_is_running() {
	if [ -S "${TYD_DIR}/tyd.sock" ]; then
		return 0
	fi
	if has_systemd_user && systemctl --user is-active --quiet tyd.service 2>/dev/null; then
		return 0
	fi
	if [ -f "${HOME_DIR}/Library/LaunchAgents/dev.getfda.tyd.plist" ]; then
		if launchctl list 2>/dev/null | grep -q 'dev.getfda.tyd'; then
			return 0
		fi
	fi
	if [ -f "${TYD_DIR}/tyd.pid" ]; then
		pid="$(cat "${TYD_DIR}/tyd.pid" 2>/dev/null || true)"
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
	fi
	return 1
}

stop_daemon() {
	stopped=0
	if has_systemd_user && systemctl --user cat tyd.service >/dev/null 2>&1; then
		systemctl --user stop tyd.service >/dev/null 2>&1 || true
		stopped=1
	fi
	plist="${HOME_DIR}/Library/LaunchAgents/dev.getfda.tyd.plist"
	if [ -f "$plist" ]; then
		launchctl unload "$plist" >/dev/null 2>&1 || true
		stopped=1
	fi
	if [ -f "${TYD_DIR}/tyd.pid" ]; then
		pid="$(cat "${TYD_DIR}/tyd.pid" 2>/dev/null || true)"
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" >/dev/null 2>&1 || true
			i=0
			while [ "$i" -lt 20 ] && kill -0 "$pid" 2>/dev/null; do
				i=$((i + 1))
				sleep 0.1
			done
			kill -9 "$pid" >/dev/null 2>&1 || true
			stopped=1
		fi
		rm -f "${TYD_DIR}/tyd.pid"
	fi
	# Drop a stale socket so the next start can bind.
	i=0
	while [ "$i" -lt 20 ] && [ -S "${TYD_DIR}/tyd.sock" ]; do
		rm -f "${TYD_DIR}/tyd.sock" 2>/dev/null || true
		i=$((i + 1))
		sleep 0.1
	done
	[ "$stopped" -eq 1 ] && log "Stopped previous tyd daemon"
}

restart_daemon() {
	log "Restarting tyd daemon with the new binary"
	stop_daemon
	start_daemon
}

is_registered() {
	[ -f "${TYD_DIR}/peers.json" ] && grep -q '"registration"' "${TYD_DIR}/peers.json"
}

mint_invite() {
	errf="$TMP/tyd-invite.err"
	# Daemon restore runs during `tyd up`; wait so invite sees the CP registration.
	i=0
	while [ "$i" -lt 50 ]; do
		if [ -S "${TYD_DIR}/tyd.sock" ]; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
	cmd=invite
	if ! is_registered; then
		cmd=register
	fi
	set -- "$TYD"
	if [ -n "$PLATFORM_URL" ]; then
		set -- "$@" --platform "$PLATFORM_URL"
	fi
	set -- "$@" "$cmd" --no-wait
	out=""
	st=0
	set +e
	out="$("$@" 2>"$errf")"
	st=$?
	set -e
	if [ "$st" -ne 0 ] && [ "$cmd" = invite ]; then
		# Local peers.json still has registration, but CP lost it (restart).
		if grep -qiE 'not found|404|restore' "$errf" 2>/dev/null; then
			log "Invite failed (CP missing registration); re-registering"
			set -- "$TYD"
			if [ -n "$PLATFORM_URL" ]; then
				set -- "$@" --platform "$PLATFORM_URL"
			fi
			set -- "$@" register --force --no-wait
			set +e
			out="$("$@" 2>"$errf")"
			st=$?
			set -e
		fi
	fi
	if [ "$st" -ne 0 ]; then
		cat "$errf" >&2 || true
		die "register/invite failed"
	fi
	if [ -z "$out" ]; then
		out="$(cat "$errf")"
	fi
	tok="$(extract_token "$out")"
	[ -n "$tok" ] || tok="$(extract_token "$(cat "$errf")")"
	[ -n "$tok" ] || die "could not parse invite token from: $out"
	print_client_bootstrap "$tok"
}

install_client() {
	log "Accepting invite"
	set -- "$TYD"
	if [ -n "$PLATFORM_URL" ]; then
		set -- "$@" --platform "$PLATFORM_URL"
	fi
	set -- "$@" accept "$ACCEPT_TOKEN"
	if [ -n "$AS_NAME" ]; then
		set -- "$@" --as "$AS_NAME"
	elif [ "$AGENT" -eq 1 ]; then
		host="$(hostname 2>/dev/null || printf client)"
		set -- "$@" --as "$host"
	fi
	"$@"
	log "Client ready. Binary: $TYD"
	log "Handbook: https://github.com/fdaio/tyd/blob/main/docs/connect.md"
}

install_server() {
	if [ "$WAS_RUNNING" -eq 1 ]; then
		restart_daemon
	else
		start_daemon
	fi
	if [ "$SERVICE_ONLY" -eq 1 ]; then
		log "Daemon ready. Binary: $TYD"
		log "It keeps running after this shell exits."
		return 0
	fi
	if [ "$AGENT" -eq 1 ] || ! have_tty; then
		mint_invite
		log "Server ready. Binary: $TYD"
		return 0
	fi
	ans="$(prompt 'Invite a client now? [Y/n]' 'Y')"
	case "$ans" in
	n | N | no | No) log "Skip invite. Later: $TYD invite --no-wait" ;;
	*) mint_invite ;;
	esac
	log "Server ready. Binary: $TYD"
	log "Handbook: https://github.com/fdaio/tyd/blob/main/docs/connect.md"
}

case ":$PATH:" in
*":$BINDIR:"*) ;;
*) log "Add ${BINDIR} to PATH (e.g. export PATH=\"${BINDIR}:\$PATH\")" ;;
esac

WAS_RUNNING=0
if daemon_is_running; then
	WAS_RUNNING=1
fi

if [ "$ROLE" = client ]; then
	install_client
else
	install_server
fi
