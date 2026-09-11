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
