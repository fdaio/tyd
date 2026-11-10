package version

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// bodyServer serves one body with a known length.
func bodyServer(t *testing.T, body []byte, withLength bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withLength {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		} else if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadFileReportsProgress(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 4096)
	srv := bodyServer(t, body, true)
	dest := filepath.Join(t.TempDir(), "tyd.tar.gz")

	var progress bytes.Buffer
	if err := downloadFile(srv.URL, dest, &progress); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("downloaded %d bytes, want %d", len(got), len(body))
	}
	out := progress.String()
	if !strings.Contains(out, "\r") {
		t.Errorf("progress should redraw one line, got %q", out)
	}
	if !strings.Contains(out, "4.0 KiB") || !strings.Contains(out, "(100%)") {
		t.Errorf("progress should report size and percent, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("progress should end its line, got %q", out)
	}
}

func TestDownloadFileProgressWithoutLength(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 4096)
	srv := bodyServer(t, body, false)
	dest := filepath.Join(t.TempDir(), "tyd.tar.gz")

	var progress bytes.Buffer
	if err := downloadFile(srv.URL, dest, &progress); err != nil {
		t.Fatal(err)
	}
	out := progress.String()
	if !strings.Contains(out, "downloaded 4.0 KiB") {
		t.Errorf("progress should report the bytes written, got %q", out)
	}
	if strings.Contains(out, "%") {
		t.Errorf("progress must not invent a percentage without a length, got %q", out)
	}
}

func TestDownloadFileSilentWithoutProgressWriter(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 4096)
	srv := bodyServer(t, body, true)
	dest := filepath.Join(t.TempDir(), "tyd.tar.gz")
	if err := downloadFile(srv.URL, dest, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("downloaded %d bytes, want %d", len(got), len(body))
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:       "0 B",
		1023:    "1023 B",
		1024:    "1.0 KiB",
		1048576: "1.0 MiB",
		3700000: "3.5 MiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
