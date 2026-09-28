package scripts_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func installScriptPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "install.sh")
}

func TestInstallScriptSyntax(t *testing.T) {
	script := installScriptPath(t)
	out, err := exec.Command("sh", "-n", script).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n %s: %v\n%s", script, err, out)
	}
}

// The installer must stay inside the invoking user's privileges: no system
// paths, and every systemctl call scoped with --user.
func TestInstallScriptStaysUserLevel(t *testing.T) {
	b, err := os.ReadFile(installScriptPath(t))
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	for _, forbidden := range []string{"/etc/systemd/system", "/Library/LaunchDaemons", "/usr/local/bin"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("install.sh must not touch %s", forbidden)
		}
	}
	for _, want := range []string{"systemctl --user", "LaunchAgents", "nohup"} {
		if !strings.Contains(body, want) {
			t.Errorf("install.sh should still use %q", want)
		}
	}

	// Upgrade must replace a running binary without ETXTBSY, then restart the daemon.
	for _, want := range []string{
		"install_binary",
		"mv -f",
		"restart_daemon",
		"daemon_is_running",
		"Stopped previous tyd daemon",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("install.sh missing upgrade path piece %q", want)
		}
	}
	if strings.Contains(body, `cp "$SRC" "${BINDIR}/tyd"`) {
		t.Error(`install.sh must not cp directly onto ${BINDIR}/tyd (ETXTBSY when daemon runs)`)
	}
	if !strings.Contains(body, "--service") {
		t.Error("install.sh should support --service for an already installed binary")
	}
	linger := strings.Index(body, "loginctl enable-linger")
	enable := strings.Index(body, "systemctl --user enable --now tyd.service")
	if linger < 0 || enable < 0 || linger > enable {
		t.Error("enable-linger must run before the user service starts")
	}
	if !strings.Contains(body, "setsid") {
		t.Error("fallback daemon start should detach with setsid")
	}

	for i, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[0] == "sudo" {
			t.Errorf("line %d runs sudo: %s", i+1, line)
		}
		if fields[0] == "systemctl" && (len(fields) < 2 || fields[1] != "--user") {
			t.Errorf("line %d uses system-wide systemctl: %s", i+1, line)
		}
	}
}

// The installer must fetch exactly one archive: its own os+arch. A shared
// per-OS tarball made every install pull the other architecture and the relay,
// 12.4MB where 3.7MB is enough.
func TestInstallScriptDownloadsOneArchiveForThisPlatform(t *testing.T) {
	b, err := os.ReadFile(installScriptPath(t))
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	// The archive name is per platform and per architecture. stable resolves
	// through /releases/latest/download/, which GitHub maps to the newest release
	// that is neither a draft nor a prerelease; edge resolves a tag of its own,
	// because a prerelease has no such alias.
	for _, want := range []string{
		`name="tyd-${os}-${arch}.tar.gz"`,
		"releases/latest/download/",
		"/releases/download/%s/",
		"release_asset_url",
		"--channel",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("install.sh should contain %q", want)
		}
	}
	// A per-OS archive is what this replaced: one file carried every
	// architecture and the relay, so every install paid for both.
	if strings.Contains(body, "tyd-${OS}.tar.gz") {
		t.Error("install.sh must not ask for the per-OS archive any more")
	}
	if strings.Contains(body, "tyd-relay") {
		t.Error("install.sh must not ship or install the relay")
	}
	// The archive holds a bare tyd; os+arch is already in the file name.
	if !strings.Contains(body, `SRC="$TMP/tyd"`) {
		t.Error(`install.sh should lift tyd out of the per-os+arch archive as $TMP/tyd`)
	}
	if strings.Contains(body, `"$TMP/${OS}/tyd-${ARCH}"`) {
		t.Error("install.sh still expects the old per-OS archive layout")
	}
	if !strings.Contains(body, "aarch64 | arm64)") || !strings.Contains(body, "x86_64 | amd64)") {
		t.Error("install.sh must keep mapping uname -m onto the archive's arch names")
	}
}

func TestInstallBinaryReplacesBusyExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	// A shell script is not mapped as the running executable (the interpreter
	// is), so cp onto it does not return ETXTBSY. Use a real ELF.
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not on PATH")
	}
	sleepData, err := os.ReadFile(sleepBin)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "tyd")
	if err := os.WriteFile(dest, sleepData, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(dest, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	newBin := filepath.Join(dir, "new")
	if err := os.WriteFile(newBin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Direct cp should fail with ETXTBSY on Linux when the file is busy.
	if runtime.GOOS == "linux" {
		if err := exec.Command("cp", newBin, dest).Run(); err == nil {
			t.Fatal("expected direct cp onto busy binary to fail on linux")
		}
	}

	script := `
set -eu
install_binary() {
	src="$1"
	dest="$2"
	tmp="${dest}.new.$$"
	cp "$src" "$tmp"
	chmod 755 "$tmp"
	mv -f "$tmp" "$dest"
}
install_binary "$1" "$2"
`
	out, err := exec.Command("sh", "-c", script, "sh", newBin, dest).CombinedOutput()
	if err != nil {
		t.Fatalf("install_binary: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "echo ok") {
		t.Fatalf("dest not replaced: %q", got)
	}
}

func TestServiceOnlyRequiresInstalledBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	dir := t.TempDir()
	cmd := exec.Command("sh", installScriptPath(t), "--service")
	cmd.Env = append(os.Environ(),
		"HOME="+dir,
		"TYD_BINDIR="+filepath.Join(dir, "bin"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure without a binary, got %s", out)
	}
	text := string(out)
	if !strings.Contains(text, "no binary") {
		t.Fatalf("output: %s", text)
	}
	if strings.Contains(text, "download failed") {
		t.Fatalf("service install tried to download: %s", text)
	}
}

// End-to-end shape of the new per-os+arch archive: one bare tyd, lifted into
// BINDIR. The fake binary then fails `accept`, which is fine — the point is
// where install.sh looks inside the tarball.
func TestInstallExtractsBareTydFromArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	fake := filepath.Join(t.TempDir(), "src", "linux-amd64", "tyd")
	if err := os.MkdirAll(filepath.Dir(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho fake tyd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	archive := filepath.Join(work, "tyd-linux-amd64.tar.gz")
	if out, err := exec.Command("tar", "-C", filepath.Dir(fake), "-czf", archive, "tyd").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, out)
	}

	home := t.TempDir()
	bindir := filepath.Join(home, "bin")
	cmd := exec.Command("sh", installScriptPath(t), "--client", "--accept", "not-a-real-token")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TYD_BINDIR="+bindir,
		"TYD_RELEASE_URL=file://"+archive,
	)
	// The stub binary is not a real tyd, so `accept` exits non-zero.
	out, _ := cmd.CombinedOutput()

	installed := filepath.Join(bindir, "tyd")
	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatalf("tyd not installed from the archive: %v\n%s", err, out)
	}
	if !strings.Contains(string(got), "fake tyd") {
		t.Fatalf("installed the wrong file: %q", got)
	}
	if !strings.Contains(string(out), "Accepting invite") {
		t.Fatalf("install should have reached the accept step:\n%s", out)
	}
}

// A per-OS style archive (tyd under an os directory) is no longer what the
// release publishes, so it must fail loudly instead of half-installing.
func TestInstallRejectsArchiveWithoutBareTyd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	work := t.TempDir()
	stage := filepath.Join(work, "linux", "tyd-amd64")
	if err := os.MkdirAll(filepath.Dir(stage), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(work, "old-style.tar.gz")
	if out, err := exec.Command("tar", "-C", filepath.Join(work, "linux"), "-czf", archive, "tyd-amd64").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, out)
	}

	home := t.TempDir()
	cmd := exec.Command("sh", installScriptPath(t), "--client", "--accept", "not-a-real-token")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TYD_BINDIR="+filepath.Join(home, "bin"),
		"TYD_RELEASE_URL=file://"+archive,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got:\n%s", out)
	}
	if !strings.Contains(string(out), "archive missing tyd") {
		t.Fatalf("expected an archive layout error, got:\n%s", out)
	}
}

// releaseArchive builds a tarball holding a stub tyd, as `make dist` does.
func releaseArchive(t *testing.T) (path string, size int) {
	t.Helper()
	dir := t.TempDir()
	stage := filepath.Join(dir, "stage", "tyd")
	if err := os.MkdirAll(filepath.Dir(stage), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("#!/bin/sh\necho fake tyd\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "tyd.tar.gz")
	if o, err := exec.Command("tar", "-C", filepath.Dir(stage), "-czf", out, "tyd").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, o)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return out, len(b)
}

// cutAfter aborts the response after n bytes, the way a throttled link gets
// reset mid-transfer. http.ErrAbortHandler drops the connection without a
// graceful close, so curl sees a partial body and a non-zero exit.
func cutAfter(w http.ResponseWriter, body []byte, n int) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		_, _ = w.Write(body[:n])
		f.Flush()
	}
	panic(http.ErrAbortHandler)
}

// A reset download must not fail the install: the loop resumes with -C - and
// keeps the bytes that already arrived.
func TestInstallResumesAResetDownload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	archive, size := releaseArchive(t)
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 512

	var mu sync.Mutex
	cuts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		start := 0
		if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
			n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rng, "bytes="), "-"))
			if err == nil {
				start = n
			}
		}
		rest := body[start:]
		w.Header().Set("Accept-Ranges", "bytes")
		if start > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(len(rest)))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(rest)))
			w.WriteHeader(http.StatusOK)
		}
		// Reset the first two attempts partway through, then serve the rest.
		if cuts < 2 {
			cuts++
			cutAfter(w, rest, chunk)
			return
		}
		_, _ = w.Write(rest)
	}))
	defer srv.Close()

	home := t.TempDir()
	bindir := filepath.Join(home, "bin")
	cmd := exec.Command("sh", installScriptPath(t), "--client", "--accept", "not-a-real-token")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TYD_BINDIR="+bindir,
		"TYD_RELEASE_URL="+srv.URL+"/tyd.tar.gz",
	)
	out, _ := cmd.CombinedOutput()

	mu.Lock()
	gotCuts := cuts
	mu.Unlock()
	if gotCuts != 2 {
		t.Fatalf("server cut %d times, want 2\n%s", gotCuts, out)
	}
	if !strings.Contains(string(out), "download interrupted") {
		t.Fatalf("install should report the interruption and retry:\n%s", out)
	}
	got, err := os.ReadFile(filepath.Join(bindir, "tyd"))
	if err != nil {
		t.Fatalf("tyd not installed after a resumed download: %v\n%s", err, out)
	}
	if !strings.Contains(string(got), "fake tyd") {
		t.Fatalf("installed the wrong file: %q", got)
	}
	if size == 0 {
		t.Fatal("empty archive fixture")
	}
}

// Some mirrors answer a Range request with the whole body. Appending to that
// would corrupt the file, so the loop drops the partial and starts over.
func TestInstallRestartsWhenServerIgnoresRange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	archive, _ := releaseArchive(t)
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	const chunk = 400

	var mu sync.Mutex
	cuts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Range") != "" {
			// No 206, no Accept-Ranges: curl reports 33.
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			if cuts < 2 {
				cuts++
				cutAfter(w, body, chunk)
				return
			}
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	home := t.TempDir()
	bindir := filepath.Join(home, "bin")
	cmd := exec.Command("sh", installScriptPath(t), "--client", "--accept", "not-a-real-token")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TYD_BINDIR="+bindir,
		"TYD_RELEASE_URL="+srv.URL+"/tyd.tar.gz",
	)
	out, _ := cmd.CombinedOutput()

	got, err := os.ReadFile(filepath.Join(bindir, "tyd"))
	if err != nil {
		t.Fatalf("tyd not installed when the server ignores Range: %v\n%s", err, out)
	}
	if !strings.Contains(string(got), "fake tyd") {
		t.Fatalf("installed the wrong file: %q", got)
	}
}

// A server that never completes the transfer must fail with the byte count, so
// the message distinguishes a network problem from a bad URL.
func TestInstallReportsBytesKeptWhenDownloadNeverCompletes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		cutAfter(w, make([]byte, 0), 16)
	}))
	defer srv.Close()

	home := t.TempDir()
	cmd := exec.Command("sh", installScriptPath(t), "--client", "--accept", "not-a-real-token")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TYD_BINDIR="+filepath.Join(home, "bin"),
		// Point at a server that always cuts: the loop must give up, not hang.
		"TYD_RELEASE_URL="+srv.URL+"/tyd.tar.gz",
		"TYD_DOWNLOAD_ATTEMPTS=2",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "download failed") {
		t.Fatalf("expected a download failure:\n%s", text)
	}
	if !strings.Contains(text, "bytes kept") {
		t.Fatalf("failure should report the bytes kept:\n%s", text)
	}
}

// bootstrapHarness runs print_client_bootstrap on its own, with have_tty
// forced either way, so the stdout/stderr split can be checked without a
// daemon and a Control Panel behind it.
func bootstrapHarness(t *testing.T, agent, tty string) (stdout, stderr string) {
	t.Helper()
	src, err := os.ReadFile(installScriptPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var fn strings.Builder
	in := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "print_client_bootstrap() {") {
			in = true
		}
		if in {
			fn.WriteString(line + "\n")
			if line == "}" {
				break
			}
		}
	}
	if fn.Len() == 0 {
		t.Fatal("print_client_bootstrap not found in install.sh")
	}

	script := `AGENT=` + agent + `
TTY_RC=` + tty + `
INSTALL_URL=https://app.getfda.dev/install.sh
PLATFORM_URL=https://app.getfda.dev
log() { printf '%s\n' "$*" >&2; }
have_tty() { [ "$TTY_RC" -eq 0 ]; }
` + fn.String() + `
print_client_bootstrap deadbeefcafe
`
	cmd := exec.Command("sh", "-c", script)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("harness: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
	return out.String(), errb.String()
}

const wantCmd = "curl -fsSL https://app.getfda.dev/install.sh | sh -s -- --client --platform https://app.getfda.dev --accept deadbeefcafe"

func TestInstallScriptPrintsBootstrapOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	tests := []struct {
		name string
		// agent selects the machine contract, tty is what have_tty reports.
		agent string
		tty   string
		// stdout carries the bare command line for agents to capture.
		wantStdout bool
		// stderr carries the block a human reads.
		wantBlock bool
		// Copies the reader sees. A TTY agent gets both: it captures stdout
		// while the person at the terminal reads the block.
		wantTotal int
	}{
		{name: "tty human", agent: "0", tty: "0", wantStdout: false, wantBlock: true, wantTotal: 1},
		{name: "tty agent", agent: "1", tty: "0", wantStdout: true, wantBlock: true, wantTotal: 2},
		{name: "no tty agent", agent: "1", tty: "1", wantStdout: true, wantBlock: false, wantTotal: 1},
		{name: "no tty", agent: "0", tty: "1", wantStdout: true, wantBlock: false, wantTotal: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr := bootstrapHarness(t, tc.agent, tc.tty)

			has := strings.TrimSpace(stdout) != ""
			if has != tc.wantStdout {
				t.Errorf("stdout present=%v, want %v (stdout=%q)", has, tc.wantStdout, stdout)
			}
			if tc.wantStdout && strings.TrimSpace(stdout) != wantCmd {
				t.Errorf("stdout = %q, want the bare command", strings.TrimSpace(stdout))
			}
			if !tc.wantStdout && strings.Contains(stdout, "curl") {
				t.Errorf("a TTY run must keep stdout clean, got %q", stdout)
			}

			block := strings.Contains(stderr, "On the client machine, run:")
			if block != tc.wantBlock {
				t.Errorf("stderr block=%v, want %v (stderr=%q)", block, tc.wantBlock, stderr)
			}
			if !tc.wantBlock && strings.Contains(stderr, "curl") {
				t.Errorf("a piped run must not repeat the command on stderr, got %q", stderr)
			}

			total := strings.Count(stdout, wantCmd) + strings.Count(stderr, wantCmd)
			if total != tc.wantTotal {
				t.Errorf("command shown %d times, want %d\nstdout: %s\nstderr: %s",
					total, tc.wantTotal, stdout, stderr)
			}
		})
	}
}
