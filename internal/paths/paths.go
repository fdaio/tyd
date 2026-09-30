package paths

import (
	"os"
	"path/filepath"
)

func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".tyd")
	}
	return filepath.Join(home, ".tyd")
}

func DefaultSocket() string {
	return filepath.Join(DefaultDir(), "tyd.sock")
}

func DefaultIdentity() string {
	return filepath.Join(DefaultDir(), "id_ed25519")
}

func DefaultTrust() string {
	return filepath.Join(DefaultDir(), "trusted.json")
}

func DefaultPeers() string {
	return filepath.Join(DefaultDir(), "peers.json")
}

// Paired is the local pairing record. It is deliberately a separate file from
// peers.json: peers.json is rebuilt from the Control Panel on every sync, so a
// peer listed there is a peer the Control Panel asked for. This one is written
// only by pairing and is the only source of trust.
func Paired() string {
	return filepath.Join(DefaultDir(), "paired.json")
}

func DefaultRecent() string {
	return filepath.Join(DefaultDir(), "recent.json")
}

func DefaultAliases() string {
	return filepath.Join(DefaultDir(), "aliases.json")
}

func DefaultSessions() string {
	return filepath.Join(DefaultDir(), "sessions.json")
}

// Archive is the client's own record of which peers and sessions are hidden
// from the default views, and when each was last used. It is a file of its own
// because peers.json is rebuilt from the Control Panel on every sync, which
// would drop both.
func Archive() string {
	return filepath.Join(DefaultDir(), "archive.json")
}

// DefaultAudit is the suggested audit log path for --audit-log.
func DefaultAudit() string {
	return filepath.Join(DefaultDir(), "audit.log")
}

// DefaultLive is where live-agent session sidecars are stored.
func DefaultLive() string {
	return filepath.Join(DefaultDir(), "live")
}

// DefaultRelay is the public rendezvous for dual-NAT fallback.
// Served as WebSocket on the Control Panel (/relay) so Cloudflare HTTPS works.
// Override with --relay; use --relay off to disable.
func DefaultRelay() string {
	return "https://app.getfda.dev/relay"
}

// DefaultListen is off: TCP/TLS is opt-in via --listen.
func DefaultListen() string {
	return "off"
}

// DefaultDataListen is auto: enable QUIC data-plane when registered with CP.
func DefaultDataListen() string {
	return "auto"
}

// DefaultAdvertise is empty: tyd publishes interface IPs automatically.
// Pass --advertise HOST only for a public hostname / explicit override.
func DefaultAdvertise() string {
	return ""
}

// DefaultPlatform is the production Control Panel base URL.
func DefaultPlatform() string {
	return "https://app.getfda.dev"
}

func DefaultServerCert() string {
	return filepath.Join(DefaultDir(), "server.crt")
}

func DefaultServerKey() string {
	return filepath.Join(DefaultDir(), "server.key")
}
