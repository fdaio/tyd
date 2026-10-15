package version

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Upgrade downloads the release tarball, verifies it, and atomically
// replaces the running binary. On success it returns the new version
// tag; the caller should re-exec or exit.
//
// Verification: SHA-256 against the checksums published alongside the
// release (checksums.txt in goreleaser convention). If no checksum is
// available the upgrade REFUSES — fail closed, like Stripe CLI.
//
// Replacement: download to temp → verify → extract → rename current
// aside to .old → rename new into place → remove .old. If the swap
// fails, .old is renamed back (rollback).
func Upgrade(info *Info) (string, error) {
	if info == nullInfo() {
		return "", fmt.Errorf("no release info")
	}
	// Refuse if installed via a package manager: we don't know who owns
	// the binary. Detect Homebrew by prefix; more managers can be added.
	if exe, err := os.Executable(); err == nil {
		if isManagedInstall(exe) {
			return "", fmt.Errorf(
				"tyd was installed via a package manager; upgrade it there " +
					"(e.g. brew upgrade tyd) instead of tyd upgrade",
			)
		}
	}

	tmpDir, err := os.MkdirTemp("", "tyd-upgrade")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tarball := filepath.Join(tmpDir, "tyd.tar.gz")
	if err := downloadFile(info.URL, tarball); err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	if err := verifyTarball(info, tarball); err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	newBin := filepath.Join(tmpDir, "tyd")
	if err := extractBinary(tarball, newBin); err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}
	if err := swapBinary(newBin); err != nil {
		return "", fmt.Errorf("replace: %w", err)
	}
	return info.Tag, nil
}

func nullInfo() *Info { return nil }

// isManagedInstall reports whether the binary lives under a known
// package manager prefix.
func isManagedInstall(exe string) bool {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// Homebrew: /opt/homebrew/bin or /usr/local/bin via Cellar.
	if strings.Contains(exe, "/Cellar/") || strings.HasPrefix(exe, "/opt/homebrew/") {
		return true
	}
	return false
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// verifyTarball checks the SHA-256 against the release's checksums.
// info.SHA256, when set, is authoritative. Otherwise we fetch
// checksums.txt next to the tarball and look up our platform's entry.
// No checksum available → error (fail closed).
func verifyTarball(info *Info, tarball string) error {
	want := info.SHA256
	if want == "" {
		var err error
		want, err = fetchChecksum(info)
		if err != nil {
			return fmt.Errorf("no checksum available, refusing: %w", err)
		}
	}
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(strings.TrimSpace(want)) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, want)
	}
	return nil
}

// fetchChecksum downloads checksums.txt from the release and finds the
// line for this platform's tarball.
func fetchChecksum(info *Info) (string, error) {
	// checksums.txt sits next to the tarball in the release.
	base := info.URL[:strings.LastIndex(info.URL, "/")+1]
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(base + "checksums.txt")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums.txt: %s", resp.Status)
	}
	want := filepath.Base(info.URL)
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == want {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", want)
}

// extractBinary pulls the tyd binary out of the tarball.
func extractBinary(tarball, dest string) error {
	f, err := os.Open(tarball)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Accept "tyd" or "./tyd" or "tyd-<os>-<arch>/tyd".
		name := strings.TrimPrefix(filepath.Base(hdr.Name), "./")
		if name != "tyd" {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		return err
	}
	return fmt.Errorf("tyd binary not found in tarball")
}

// swapBinary atomically replaces the running binary.
// Unix: rename is atomic; the running process keeps its inode.
// Windows: the running binary is locked, so this fails — callers on
// Windows should use the .old dance (not implemented: tyd doesn't
// ship native Windows).
func swapBinary(newBin string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	oldBin := exe + ".old"
	// Move current aside; on failure nothing has changed.
	if err := os.Rename(exe, oldBin); err != nil {
		return fmt.Errorf("move current aside: %w", err)
	}
	// Move new into place; on failure roll back.
	if err := os.Rename(newBin, exe); err != nil {
		_ = os.Rename(oldBin, exe) // best-effort rollback
		return fmt.Errorf("install new binary: %w (rolled back)", err)
	}
	// Success: remove the backup.
	_ = os.Remove(oldBin)
	if runtime.GOOS != "windows" {
		_ = os.Chmod(exe, 0o755)
	}
	return nil
}
