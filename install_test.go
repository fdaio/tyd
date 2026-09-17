package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallScriptSyntax(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	script := filepath.Join(filepath.Dir(file), "scripts", "install.sh")
	out, err := exec.Command("sh", "-n", script).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n %s: %v\n%s", script, err, out)
	}
}
