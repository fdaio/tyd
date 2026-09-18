// Package safefile writes files without destroying what is already there.
//
// os.WriteFile truncates before it writes, so a full disk or a crash halfway
// through leaves the old content gone and the new content incomplete. Every
// tyd state file goes through WriteFile here instead: the data lands in a
// temporary file in the same directory, is flushed, and only then replaces the
// target with a rename. A failed write leaves the previous file untouched.
package safefile

import (
	"os"
	"path/filepath"
)

// WriteFile atomically replaces path with data.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// Flush before the rename so a crash cannot publish an empty file.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	syncDir(dir)
	return nil
}

// syncDir persists the rename itself. Failure here costs durability, not
// correctness, so it is best effort.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
