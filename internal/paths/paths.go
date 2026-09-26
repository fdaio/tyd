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

func DefaultRecent() string {
	return filepath.Join(DefaultDir(), "recent.json")
}

func DefaultAliases() string {
	return filepath.Join(DefaultDir(), "aliases.json")
}

func DefaultSessions() string {
	return filepath.Join(DefaultDir(), "sessions.json")
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
// Override with --relay; use --relay off to disable.
func DefaultRelay() string {
	return "https://relay.getfda.dev"
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
