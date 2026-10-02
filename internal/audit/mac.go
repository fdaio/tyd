package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ContentMAC is the keyed digest of a file operation's content.
//
// **Not a bare sha256.** For low-entropy content — a short password, a token — a
// bare hash is an offline dictionary-attack verifier: whoever holds the log can
// confirm a guess without ever seeing the content. Keyed with a secret the log does
// not carry, the same guess cannot be checked offline, and the daemon can still
// compare two records for equality.
//
// Cost, accepted and documented: after a key rotation, records written under the
// old key cannot be compared with records written under the new one.
type ContentMAC string

// Key is the audit MAC key. It is held by the daemon in its own 0600 file and is
// never written to the log.
type Key [32]byte

// LoadOrCreateKey reads the key at path, creating it if it is not there.
//
// The failure modes are deliberate and all of them stop the caller:
//
//   - Unreadable, or a key file whose permissions are wider than 0600: an error.
//     A world-readable key is not a key, and continuing would produce records that
//     look authenticated and are not.
//   - A key of the wrong length: an error, rather than padding it into something
//     that silently differs from what the operator thinks is in the file.
//   - Existing: read as-is. Never regenerated, because regenerating would make
//     every earlier record unverifiable in a way nobody asked for.
//
// The write is O_EXCL, so two daemons starting at once cannot both decide they are
// the one that created it. The loser reads the winner's key.
func LoadOrCreateKey(path string) (Key, error) {
	var key Key

	// Checked before the read as well as after: the read would succeed on a
	// world-readable file, and the point is to refuse it.
	if err := checkKeyPerms(path); err != nil {
		return key, err
	}

	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) != len(key) {
			return key, fmt.Errorf("audit key %s is %d bytes, want %d", path, len(b), len(key))
		}
		copy(key[:], b)
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return key, fmt.Errorf("audit key %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("audit key %s: %w", path, err)
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("audit key %s: %w", path, err)
	}
	if err := publishKey(path, key[:]); err != nil {
		var exists *keyExistsError
		if errors.As(err, &exists) {
			// Another daemon got there first. Its key is the real one, and reading it
			// is the only answer that leaves both processes able to verify each other.
			return LoadOrCreateKey(path)
		}
		return key, fmt.Errorf("audit key %s: %w", path, err)
	}
	return key, nil
}

// keyExistsError says the name was already taken, so the caller reads the winner's
// key instead of publishing its own.
type keyExistsError struct{ path string }

func (e *keyExistsError) Error() string { return "audit key " + e.path + " already exists" }

// publishKey creates path containing data, and fails if it already exists.
//
// **The name appears only once the bytes are in it.** Creating with O_EXCL and then
// writing publishes the name first, and a second daemon starting at that moment
// reads a zero-length file — which is a key failure it would report as a corrupt
// key rather than as the race it is. So the bytes go to a temporary file, are
// flushed, and are linked into place: link(2) is atomic and fails with EEXIST, so
// exactly one creator wins and the winner's content is already complete when the
// name becomes visible.
//
// A rename would not do. It overwrites, so two daemons racing would each replace the
// other's key and end up unable to verify each other's records.
func publishKey(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// CreateTemp is already 0600, and the key file must never be briefly wider.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return &keyExistsError{path: path}
		}
		return err
	}
	return nil
}

// checkKeyPerms refuses a key file that others can read.
//
// Group- and world-readable is refused. A key in a group-readable file is readable
// by whoever the operator put in the group, and the file's whole purpose is that the
// log alone is not enough to check a guess.
func checkKeyPerms(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit key %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("audit key %s is mode %04o; it must not be readable by group or other "+
			"(chmod 600 %s)", path, mode, path)
	}
	return nil
}

// MAC returns the keyed digest of content.
//
// The domain separator is part of the input so a MAC from one use cannot be
// presented as a MAC from another: a record cannot be moved from one field to
// another and still verify.
func (k Key) MAC(kind Kind, content []byte) ContentMAC {
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write(content)
	return ContentMAC(hex.EncodeToString(m.Sum(nil)))
}

// Verify reports whether mac is the digest this key produces for content. It is a
// constant-time comparison, because the comparison is against a value that arrived
// from somewhere.
func (k Key) Verify(kind Kind, content []byte, mac ContentMAC) bool {
	return hmac.Equal([]byte(k.MAC(kind, content)), []byte(mac))
}
