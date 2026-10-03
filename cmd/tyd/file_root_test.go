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

// The refusals have to happen on the path a daemon actually takes.
//
// resolveFileRoot is unit-tested above and was correct the whole time; it was called
// from one place — the __live-agent child — while `tyd serve` and `tyd mcp` read
// opts.fileRoot directly. So `--file-root /` was accepted by every command anyone runs,
// and the tests passed, because they tested the helper rather than the wiring. These
// go through run() so a second caller cannot quietly bypass it again.
func TestTheFileRootRefusalsApplyToEveryCommand(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory here: %v", err)
	}
	for _, argv := range [][]string{
		{"--file-root", "/", "mcp"},
		{"--file-root", "/", "serve"},
		{"--file-root", home, "mcp"},
		{"--file-root", "/no/such/directory/anywhere", "mcp"},
	} {
		opts, err := parseArgs(argv)
		if err != nil {
			t.Fatalf("%v did not even parse: %v", argv, err)
		}
		err = run(opts)
		if err == nil {
			t.Errorf("%v was accepted; a command must not be able to bypass the refusals", argv)
			continue
		}
		// The message has to say which flag, or an operator sees a refusal with nothing
		// to act on.
		if !strings.Contains(err.Error(), "--file-root") {
			t.Errorf("%v was refused with %q, which does not name the flag", argv, err)
		}
	}
}

// A relative root is made absolute once, at the point it is resolved, so the value
// handed to an agent is the same directory this process decided on.
func TestARelativeFileRootIsResolvedBeforeItIsUsed(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveFileRoot("sub", false)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("resolved to %q, which is still relative", got)
	}
	// Compared through EvalSymlinks because t.TempDir() sits under /var, which on
	// macOS is a symlink to /private/var, so the two spellings differ while the
	// directory is the same.
	want, err := filepath.EvalSymlinks(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("resolved to %q, want %q", got, want)
	}
}
