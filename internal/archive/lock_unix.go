//go:build unix

package archive

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive lock on path and returns the func that releases
// it. The lock is what makes two tyd processes pruning at the same moment take
// turns instead of each dropping the other's mark.
func lockFile(path string) (func(), error) {
	// safefile.WriteFile creates the state directory, and the lock is taken
	// before that runs. Creating it here too keeps a first run — where nothing
	// has been written yet — from reporting a missing directory.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
