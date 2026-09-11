package paths

import (
	"os"
	"path/filepath"
)

func DefaultSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "tyd.sock")
	}
	return filepath.Join(home, ".tyd", "tyd.sock")
}
