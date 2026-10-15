package version

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyTarball(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "test.tar.gz")
	content := []byte("fake tarball content")
	if err := os.WriteFile(tarball, content, 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	want := hex.EncodeToString(h[:])

	// Correct checksum passes.
	info := &Info{Tag: "v1.0.0", SHA256: want}
	if err := verifyTarball(info, tarball); err != nil {
		t.Errorf("verifyTarball with correct checksum: %v", err)
	}

	// Wrong checksum fails.
	info.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := verifyTarball(info, tarball); err == nil {
		t.Error("verifyTarball with wrong checksum: expected error, got none")
	}

	// No checksum and no way to fetch → fail closed.
	info.SHA256 = ""
	info.URL = "https://invalid.example.com/nonexistent/tyd.tar.gz"
	if err := verifyTarball(info, tarball); err == nil {
		t.Error("verifyTarball with no checksum: expected fail-closed error, got none")
	}
}

func TestIsManagedInstall(t *testing.T) {
	// Homebrew paths are managed.
	if !isManagedInstall("/opt/homebrew/Cellar/tyd/1.0.0/bin/tyd") {
		t.Error("Homebrew Cellar path should be managed")
	}
	if !isManagedInstall("/opt/homebrew/bin/tyd") {
		t.Error("/opt/homebrew/bin should be managed")
	}
	// ~/.local/bin is not managed.
	if isManagedInstall("/home/user/.local/bin/tyd") {
		t.Error("~/.local/bin should not be managed")
	}
}
