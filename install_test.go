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
