#!/bin/sh
# tyd one-click install: GitHub release binary + pairing bootstrap.
# Human (TTY): choose server or client; server can mint a copy-paste client command.
# Agent / non-TTY: --agent (default server) or --client --accept TOKEN.
set -eu

REPO="${TYD_REPO:-fdaio/tyd}"
INSTALL_URL="${TYD_INSTALL_URL:-}"
PLATFORM_URL="${TYD_PLATFORM:-}"
ROLE=""
ACCEPT_TOKEN=""
AGENT=0
AS_NAME=""

usage() {
	cat <<'EOF'
Install tyd from GitHub Releases.

Usage:
  curl -fsSL https://app.getfda.dev/install.sh | sh
  curl -fsSL ... | sh -s -- --agent
  curl -fsSL ... | sh -s -- --client --accept TOKEN

Options:
  --server            Install as server (this machine holds sessions)
  --client            Install as client (no daemon)
  --agent             Non-interactive server; print client bootstrap and exit
  --accept TOKEN      Invite token (client)
  --as NAME           Peer nickname when accepting
  --platform URL      Control Panel URL
  -h, --help          Show this help

Env: TYD_REPO, TYD_INSTALL_URL, TYD_PLATFORM, TYD_BINDIR
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

if [ -n "${TYD_BINDIR:-}" ]; then
	BINDIR="$TYD_BINDIR"
elif [ "$(id -u)" -eq 0 ]; then
	BINDIR="/usr/local/bin"
else
	BINDIR="${HOME}/.local/bin"
fi

HOME_DIR="${HOME:-/tmp}"
TYD_DIR="${HOME_DIR}/.tyd"
mkdir -p "$BINDIR" "$TYD_DIR"

log "Installing tyd (${OS}/${ARCH}) to ${BINDIR}/tyd"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT HUP
ARCHIVE="$TMP/tyd.tgz"
URL="https://github.com/${REPO}/releases/latest/download/tyd-${OS}.tar.gz"
if ! curl -fsSL --retry 3 -o "$ARCHIVE" "$URL"; then
	die "download failed: $URL (publish a v* GitHub release, or build with make build)"
fi
tar -xzf "$ARCHIVE" -C "$TMP"
SRC="$TMP/${OS}/tyd-${ARCH}"
[ -f "$SRC" ] || die "archive missing ${OS}/tyd-${ARCH}"
cp "$SRC" "${BINDIR}/tyd"
chmod 755 "${BINDIR}/tyd"
TYD="${BINDIR}/tyd"
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

has_systemd_system() {
	[ "$(id -u)" -eq 0 ] || return 1
	command -v systemctl >/dev/null 2>&1 || return 1
	systemctl show-environment >/dev/null 2>&1
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
	systemctl --user daemon-reload
	systemctl --user enable --now tyd.service
	loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
	log "Started tyd via systemd --user (tyd.service)"
}

start_daemon_systemd_system() {
	cat >/etc/systemd/system/tyd.service <<UNIT
[Unit]
Description=tyd session daemon
After=network-online.target

[Service]
ExecStart=${TYD} up
Restart=on-failure
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
UNIT
	systemctl daemon-reload
	systemctl enable --now tyd.service
	log "Started tyd via systemd (tyd.service)"
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
	if [ -S "${TYD_DIR}/tyd.sock" ]; then
		log "tyd socket already present; not starting another daemon"
		return 0
	fi
	nohup "$TYD" up >>"${TYD_DIR}/tyd.log" 2>&1 &
	printf '%s\n' "$!" >"${TYD_DIR}/tyd.pid"
	log "Started tyd with nohup (pid $(cat "${TYD_DIR}/tyd.pid"), log ${TYD_DIR}/tyd.log)"
}

start_daemon() {
	case "$OS" in
	linux)
		if has_systemd_system; then
			start_daemon_systemd_system
		elif has_systemd_user; then
			start_daemon_systemd_user
		else
			start_daemon_nohup
		fi
		;;
	darwin)
		start_daemon_launchd
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
	log "warning: tyd.sock not seen yet; check ${TYD_DIR}/tyd.log"
}

is_registered() {
	[ -f "${TYD_DIR}/peers.json" ] && grep -q '"registration"' "${TYD_DIR}/peers.json"
}

mint_invite() {
	errf="$TMP/tyd-invite.err"
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
	log "Handbook: https://github.com/${REPO}/blob/main/docs/connect.md"
}

install_server() {
	start_daemon
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
	log "Handbook: https://github.com/${REPO}/blob/main/docs/connect.md"
}

case "$BINDIR" in
"${HOME}/.local/bin")
	case ":$PATH:" in
	*":$BINDIR:"*) ;;
	*) log "Add ${BINDIR} to PATH (e.g. export PATH=\"${BINDIR}:\$PATH\")" ;;
	esac
	;;
esac

if [ "$ROLE" = client ]; then
	install_client
else
	install_server
fi
