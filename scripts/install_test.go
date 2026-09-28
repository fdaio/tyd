package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

	const want = "releases/latest/download/tyd-${OS}-${ARCH}.tar.gz"
	if !strings.Contains(body, want) {
		t.Errorf("install.sh should download %s", want)
	}
	// The old fat archive is gone; its URL would still resolve to every
	// architecture, which is the download this change removes.
	if strings.Contains(body, "download/tyd-${OS}.tar.gz") {
		t.Error("install.sh must not download the per-OS archive any more")
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
