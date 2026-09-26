package main

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
	return filepath.Join(filepath.Dir(file), "scripts", "install.sh")
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

func TestInstallBinaryReplacesBusyExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix only")
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "tyd")
	if err := os.WriteFile(dest, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(dest)
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
