//go:build !unix

package archive

import (
	"os"
	"path/filepath"
)

// lockFile holds nothing where flock does not exist, and only opens the file so
// that an unwritable state directory still fails here. Two processes pruning at
// the same moment can then drop a mark each. A mark is a display state that the
// next prune writes back, so the cost is one stale view.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
