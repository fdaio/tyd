package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `/` is refused with no switch. A flag that permits the filesystem root is a flag
// that turns off the only guarantee the feature makes, so this asserts there is no
// value of allowHome that lets it through.
func TestTheFilesystemRootIsRefusedWithNoSwitch(t *testing.T) {
	for _, allowHome := range []bool{false, true} {
		if _, err := resolveFileRoot("/", allowHome); err == nil {
			t.Errorf("/ was accepted with allowHome=%v", allowHome)
		}
	}
	if _, err := resolveFileRoot(string(filepath.Separator), true); err == nil {
		t.Error("/ was accepted")
	}
}

// $HOME is available, and never silent.
func TestHomeIsRefusedUnlessAskedFor(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory here: %v", err)
	}
	_, err = resolveFileRoot(home, false)
	if err == nil {
		t.Fatal("$HOME was accepted without the switch")
	}
	if !strings.Contains(err.Error(), "--file-root-allow-home") {
		t.Errorf("the refusal does not name the switch that permits it: %v", err)
	}
	got, err := resolveFileRoot(home, true)
	if err != nil {
		t.Fatalf("$HOME was refused even with the switch: %v", err)
	}
	if got != filepath.Clean(home) {
		t.Errorf("got %q, want the cleaned home %q", got, filepath.Clean(home))
	}
}

// A root that is not a directory, or not there, is an error at startup rather than
// an agent that answers every request with "unavailable".
func TestAFileRootMustBeADirectoryThatExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveFileRoot(file, false); err == nil {
		t.Error("a file was accepted as a root")
	}
	if _, err := resolveFileRoot(filepath.Join(dir, "missing"), false); err == nil {
		t.Error("a missing directory was accepted as a root")
	}
	// A trailing slash and a relative path both resolve, because an operator
	// typing them should not have to know which form the program wants.
	for _, given := range []string{dir, dir + "/", dir + "/./"} {
		got, err := resolveFileRoot(given, false)
		if err != nil {
			t.Errorf("%q: %v", given, err)
			continue
		}
		if got != filepath.Clean(dir) {
			t.Errorf("%q resolved to %q, want %q", given, got, filepath.Clean(dir))
		}
	}
}

// No --file-root is the default and means the operations do not exist. The flag
// parser has to leave it empty rather than filling in a default path.
func TestNoFileRootMeansNone(t *testing.T) {
	opts, err := parseArgs([]string{"session", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.fileRoot != "" {
		t.Errorf("--file-root defaulted to %q; there is no default root", opts.fileRoot)
	}
	if opts.fileRootAllowHome {
		t.Error("--file-root-allow-home defaulted to set")
	}
	for _, argv := range [][]string{
		{"--file-root", "/tmp/whatever", "session", "list"},
		{"--file-root=/tmp/whatever", "session", "list"},
	} {
		opts, err := parseArgs(argv)
		if err != nil {
			t.Fatal(err)
		}
		if opts.fileRoot != "/tmp/whatever" {
			t.Errorf("%v gave %q", argv, opts.fileRoot)
		}
	}
	if _, err := parseArgs([]string{"session", "list", "--file-root"}); err == nil {
		t.Error("--file-root with nothing after it was accepted")
	}
}
