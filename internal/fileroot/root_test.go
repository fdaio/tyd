package fileroot_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"tyd/internal/fileroot"
)

func openRoot(t *testing.T) (*fileroot.Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func codeOf(t *testing.T, err error) fileroot.Code {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	c := fileroot.CodeOf(err)
	if c == "" {
		t.Fatalf("error %v carries no code", err)
	}
	return c
}

// A read is a read: bytes in, bytes out, no terminal semantics anywhere.
func TestReadReturnsBytesVerbatim(t *testing.T) {
	r, dir := openRoot(t)
	content := "line one\nline two\x1b[31mred\x1b[0m\n"
	write(t, dir, "a.txt", content)

	got, err := r.Read("a.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != content {
		t.Errorf("content was altered:\n got %q\nwant %q", got.Data, content)
	}
	if got.Size != int64(len(content)) || got.Truncated {
		t.Errorf("size=%d truncated=%v, want %d/false", got.Size, got.Truncated, len(content))
	}
	sum := sha256.Sum256([]byte(content))
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("digest %q does not match the content", got.SHA256)
	}
}

func TestReadCapsAndSaysSo(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "big.txt", strings.Repeat("x", 500))

	got, err := r.Read("big.txt", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 100 || !got.Truncated {
		t.Errorf("got %d bytes truncated=%v, want 100/true", len(got.Data), got.Truncated)
	}
	if got.Size != 500 {
		t.Errorf("size=%d, want the whole file's 500 so a caller can tell", got.Size)
	}
	// The hash covers the whole file, so a caller that read a prefix can still use
	// it as a concurrency guard.
	sum := sha256.Sum256([]byte(strings.Repeat("x", 500)))
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the digest covers only what was returned, so it cannot guard a write")
	}
}

func TestReadFromAnOffset(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "a.txt", "0123456789")
	got, err := r.Read("a.txt", 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "456789" {
		t.Errorf("got %q, want 456789", got.Data)
	}
	if got.Truncated {
		t.Error("reading to the end should not report truncation")
	}
}

// A FIFO must not block the open forever, and a device is worse. O_NONBLOCK then a
// type check, in that order: an fstat after a blocking open is too late.
func TestReadRefusesAnythingButARegularFile(t *testing.T) {
	r, dir := openRoot(t)

	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("no fifo here: %v", err)
	}
	_, err := r.Read("pipe", 0, 0)
	if got := codeOf(t, err); got != fileroot.CodeNotRegular {
		t.Errorf("a fifo gave %q, want not_regular", got)
	}

	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = r.Read("sub", 0, 0)
	if got := codeOf(t, err); got != fileroot.CodeNotRegular {
		t.Errorf("a directory gave %q, want not_regular", got)
	}

	_, err = r.Read("nope.txt", 0, 0)
	if got := codeOf(t, err); got != fileroot.CodeNotFound {
		t.Errorf("a missing file gave %q, want not_found", got)
	}
}

// The whole point: nothing above the root is reachable, by any route.
func TestNothingAboveTheRootIsReachable(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "root")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := fileroot.Open(sub)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	for _, name := range []string{
		"../outside/secret.txt",
		"../../etc/passwd",
		"/etc/passwd",
		"sub/../../outside/secret.txt",
	} {
		if _, err := r.Read(name, 0, 0); err == nil {
			t.Errorf("%q was read through the root", name)
		}
	}
	if _, err := r.Write("../outside/new.txt", []byte("x"), fileroot.ModeCreate, ""); err == nil {
		t.Error("a write escaped the root")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); err == nil {
		t.Error("a file was created outside the root")
	}
}

// A symlinked final component is refused by the kernel, atomically. An Lstat then an
// open would leave a window; this asserts the refusal happens, not how.
func TestASymlinkedFileIsRefused(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "real.txt", "original")
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if _, err := r.Read("link.txt", 0, 0); err == nil {
		t.Error("a read followed a symlink")
	}
	if _, err := r.Write("link.txt", []byte("clobbered"), fileroot.ModeReplace, ""); err == nil {
		t.Error("a write followed a symlink")
	}
	got, err := r.Read("real.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "original" {
		t.Errorf("the target was written through its link: %q", got.Data)
	}
}

// The concession, pinned. A symlinked intermediate *directory* is followed, because
// os.Root allows it while it stays inside — and a test that would notice this
// changing is the point of writing it down.
func TestASymlinkedDirectoryRedirectsWithinTheRoot(t *testing.T) {
	r, dir := openRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "real/inner.txt", "inside")
	if err := os.Symlink("real", filepath.Join(dir, "alias")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	got, err := r.Read("alias/inner.txt", 0, 0)
	if err != nil {
		t.Fatalf("a symlinked directory inside the root was refused: %v", err)
	}
	if string(got.Data) != "inside" {
		t.Errorf("got %q, want the content inside the root", got.Data)
	}
}

// The race the brief asks for: swap a directory component for a symlink pointing
// outside, over and over, while reads and writes run. Nothing may ever escape.
func TestASymlinkSwapNeverEscapesTheRoot(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	outside := filepath.Join(dir, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := fileroot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		flip := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			link := filepath.Join(root, "sub")
			if flip {
				_ = os.Remove(link)
			} else {
				_ = os.Symlink(outside, link)
			}
			flip = !flip
		}
	}()

	for i := 0; i < 400; i++ {
		res, err := r.Read("sub/secret.txt", 0, 0)
		if err == nil && string(res.Data) == "not yours" {
			t.Fatal("a read escaped the root while a directory component was being swapped")
		}
		if err == nil {
			t.Fatalf("sub/secret.txt resolved at all, to %q", res.Data)
		}
		if _, err := r.Write("sub/new.txt", []byte("x"), fileroot.ModeCreate, ""); err == nil {
			t.Error("a write escaped the root while a directory component was being swapped")
			break
		}
	}
	close(stop)
	swapper.Wait()

	if _, err := os.Stat(filepath.Join(outside, "new.txt")); err == nil {
		t.Error("a file was created outside the root")
	}
}

// Denied by name, before anything is opened. A refusal must not depend on whether
// the path exists, or it leaks that.
func TestSensitivePathsAreRefusedByName(t *testing.T) {
	r, dir := openRoot(t)
	for _, name := range []string{".ssh/id_rsa", "sub/.ssh/config", ".gnupg/secring.gpg", ".aws/credentials"} {
		if _, err := r.Read(name, 0, 0); codeOf(t, err) != fileroot.CodeBlockedPath {
			t.Errorf("read of %s was not blocked", name)
		}
		if _, err := r.Write(name, []byte("x"), fileroot.ModeCreate, ""); codeOf(t, err) != fileroot.CodeBlockedPath {
			t.Errorf("write of %s was not blocked", name)
		}
	}
	// The code-execution paths are write-only refusals: reading them is not a way to
	// run anything.
	for _, name := range []string{".git/hooks/pre-commit", ".bashrc", ".zshrc", "sub/.profile"} {
		if _, err := r.Write(name, []byte("x"), fileroot.ModeCreate, ""); codeOf(t, err) != fileroot.CodeBlockedPath {
			t.Errorf("write of %s was not blocked", name)
		}
	}
	_ = dir
}

func TestTheDenialDoesNotRevealExistence(t *testing.T) {
	// The whole reason the decision is lexical: a refusal has to be the same answer
	// whether or not the path is there, or it tells a caller what exists.
	r, dir := openRoot(t)
	write(t, dir, ".bashrc", "existing")
	_, errExisting := r.Write(".bashrc", []byte("x"), fileroot.ModeCreate, "")
	_, errAbsent := r.Write("sub/.bashrc", []byte("x"), fileroot.ModeCreate, "")
	if errExisting == nil || errAbsent == nil {
		t.Fatal("a blocked write was allowed")
	}
	if fileroot.CodeOf(errExisting) != fileroot.CodeBlockedPath ||
		fileroot.CodeOf(errAbsent) != fileroot.CodeBlockedPath {
		t.Errorf("codes differ: %q vs %q", errExisting, errAbsent)
	}
}

func TestOrdinaryPathsAreNotOverBlocked(t *testing.T) {
	// A deny list long enough to be thorough starts refusing files people need,
	// which is how a deny list gets turned off wholesale.
	r, dir := openRoot(t)
	// The parent directories have to exist, or this measures not_found and the
	// denylist is never consulted.
	for _, d := range []string{"docs", "src/git", "project/ssh", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		".env.example", ".sshconfig", "docs/.bashrc.md", "src/git/hooks.go",
		"project/ssh/notes.txt", "data/envs.json",
	} {
		if _, err := r.Write(name, []byte("x"), fileroot.ModeCreate, ""); err != nil {
			t.Errorf("refused an ordinary path %s: %v", name, err)
		}
	}
	_ = dir
}

// create never truncates; replace never creates.
func TestWriteModesAreOpposites(t *testing.T) {
	r, dir := openRoot(t)

	if _, err := r.Write("new.txt", []byte("first"), fileroot.ModeCreate, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write("new.txt", []byte("second"), fileroot.ModeCreate, ""); codeOf(t, err) != fileroot.CodeExists {
		t.Error("create overwrote an existing file")
	}
	got, _ := r.Read("new.txt", 0, 0)
	if string(got.Data) != "first" {
		t.Errorf("content is %q, want the first write", got.Data)
	}

	if _, err := r.Write("absent.txt", []byte("x"), fileroot.ModeReplace, ""); codeOf(t, err) != fileroot.CodeNotFound {
		t.Error("replace created a file that was not there")
	}
	if _, err := r.Write("new.txt", []byte("second"), fileroot.ModeReplace, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = r.Read("new.txt", 0, 0)
	if string(got.Data) != "second" {
		t.Errorf("content is %q, want the replacement", got.Data)
	}
	_ = dir
}

// A write that is refused must leave the original exactly as it was, and must not
// leave a temporary file behind.
func TestAFailedWriteLeavesNothingBehind(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "target.txt", "original")
	if err := os.Chmod(filepath.Join(dir, "target.txt"), 0o400); err != nil {
		t.Fatal(err)
	}
	// A hash that does not match refuses before anything is written.
	if _, err := r.Write("target.txt", []byte("new"), fileroot.ModeReplace, strings.Repeat("0", 64)); codeOf(t, err) != fileroot.CodeConflict {
		t.Error("a mismatched expected_sha256 was not refused")
	}
	got, err := r.Read("target.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "original" {
		t.Errorf("the original changed: %q", got.Data)
	}
	// No temporary file, which is the other half: a crash-recovery path that leaves
	// them is how a directory slowly fills with dotfiles.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "tyd-tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestExpectedSHA256GuardsAgainstAConcurrentChange(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "f.txt", "v1")
	sum := sha256.Sum256([]byte("v1"))
	good := hex.EncodeToString(sum[:])

	if _, err := r.Write("f.txt", []byte("v2"), fileroot.ModeReplace, good); err != nil {
		t.Fatal(err)
	}
	// The same guard against content that has moved on.
	_, err := r.Write("f.txt", []byte("v3"), fileroot.ModeReplace, good)
	if codeOf(t, err) != fileroot.CodeConflict {
		t.Errorf("a stale expected_sha256 was accepted: %v", err)
	}
	got, _ := r.Read("f.txt", 0, 0)
	if string(got.Data) != "v2" {
		t.Errorf("content is %q, want v2 untouched", got.Data)
	}
	_ = dir
}

// Permissions survive a replacement, which is the point of setting them on the
// descriptor rather than the path.
func TestReplacementPreservesPermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permission bits are not a meaningful check")
	}
	r, dir := openRoot(t)
	full := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	res, err := r.Write("script.sh", []byte("#!/bin/sh\necho hi\n"), fileroot.ModeReplace, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode.Perm() != 0o750 {
		t.Errorf("mode is %o, want the original 750", res.Mode.Perm())
	}
}

// The root is a descriptor, so moving or deleting the directory does not break it —
// and that is defined behaviour rather than a surprise.
func TestTheRootSurvivesItsDirectoryMoving(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("here"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	moved := filepath.Join(base, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Skipf("cannot rename here: %v", err)
	}
	got, err := r.Read("a.txt", 0, 0)
	if err != nil {
		t.Fatalf("the root stopped working after its directory moved: %v", err)
	}
	if string(got.Data) != "here" {
		t.Errorf("got %q", got.Data)
	}
}

func TestCapsAreEnforced(t *testing.T) {
	r, dir := openRoot(t)
	write(t, dir, "a.txt", "x")
	if _, err := r.Read("a.txt", 0, fileroot.MaxReadBytes+1); codeOf(t, err) != fileroot.CodeTooLarge {
		t.Error("a read above the ceiling was allowed")
	}
	big := make([]byte, fileroot.MaxWriteBytes+1)
	if _, err := r.Write("b.bin", big, fileroot.ModeCreate, ""); codeOf(t, err) != fileroot.CodeTooLarge {
		t.Error("a write above the ceiling was allowed")
	}
	_ = dir
}

func TestErrorsCarryNoAbsolutePath(t *testing.T) {
	// An error is text a model may see, and a path above the root is not the model's
	// to have.
	r, dir := openRoot(t)
	secret := filepath.Join(dir, "..", "outside-secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := r.Read("../outside-secret.txt", 0, 0)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	if strings.Contains(msg, dir) || strings.Contains(msg, "/var/folders") {
		t.Errorf("the error leaks an absolute path: %q", msg)
	}
}

// The refusal os.Root does not give on its own, pinned so a Go change cannot quietly
// restore the following behaviour. This is the finding that made the design's
// os.Root section wrong.
func TestTheSymlinkRefusalIsOursNotGoStands(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}

	// Documented behaviour of os.Root, asserted here so the difference is visible:
	// a caller's own O_NOFOLLOW does not survive the trip.
	raw, _ := os.OpenRoot(dir)
	defer raw.Close()
	f, err := raw.OpenFile("link.txt", os.O_RDONLY, 0)
	if err == nil {
		f.Close()
		t.Log("note: this Go version refuses a final symlink through os.Root; " +
			"the explicit openat below is what makes it independent of that")
	} else {
		t.Logf("note: os.Root itself refused the link here (%v)", err)
	}

	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Read("link.txt", 0, 0); fileroot.CodeOf(err) != fileroot.CodeSymlink {
		t.Errorf("read of a symlink gave %q, want symlink", fileroot.CodeOf(err))
	}
	// Both directions, including a dangling link: Lstat reports the link, so a write
	// to one is not silently treated as a create.
	if err := os.Symlink("gone.txt", filepath.Join(dir, "dangling.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write("dangling.txt", []byte("x"), fileroot.ModeCreate, ""); fileroot.CodeOf(err) != fileroot.CodeSymlink {
		t.Errorf("write to a dangling symlink gave %q, want symlink", fileroot.CodeOf(err))
	}
	if _, err := os.Lstat(filepath.Join(dir, "gone.txt")); err == nil {
		t.Error("a write followed a dangling symlink and created its target")
	}
}

func TestDeniedIsDistinctFromTheRest(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permission bits are not a meaningful check")
	}
	dir := t.TempDir()
	name := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(name, []byte("secret"), 0o000); err != nil {
		t.Fatal(err)
	}
	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Read("locked.txt", 0, 0); fileroot.CodeOf(err) != fileroot.CodeDenied {
		t.Errorf("an unreadable file gave %q, want denied so an operator knows to chmod", fileroot.CodeOf(err))
	}
}

// The kernel does the refusing, so the check cannot be raced by swapping the entry
// between a lookup and an open. A tight loop around both directions.
func TestTheOpenRefusesSymlinksUnderConcurrentChurn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			name := filepath.Join(dir, "flip.txt")
			if i%2 == 0 {
				_ = os.Remove(name)
				_ = os.WriteFile(name, []byte("plain"), 0o644)
			} else {
				_ = os.Remove(name)
				_ = os.Symlink("real.txt", name)
			}
		}
	}()
	for i := 0; i < 500; i++ {
		res, err := r.Read("flip.txt", 0, 0)
		if err != nil {
			continue
		}
		// Whichever entry was there, the bytes must be the plain file's. Reading
		// "original" would mean the link was followed.
		if string(res.Data) == "original" {
			t.Fatal("a read returned the symlink's target while the entry was being swapped")
		}
	}
	close(stop)
	<-done
}

// The root is a descriptor, so it survives its directory being renamed — and being
// deleted has to be defined too, not merely unspecified.
func TestTheRootSurvivesItsDirectoryBeingDeleted(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("still here"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	// Whether the read still succeeds depends on the platform keeping the unlinked
	// directory alive behind the descriptor. Either answer is fine; what must not
	// happen is a hang, a wrong code, or a panic.
	got, err := r.Read("a.txt", 0, 0)
	if err != nil {
		if c := fileroot.CodeOf(err); c == "" {
			t.Errorf("a read on a deleted root gave an uncoded error: %v", err)
		}
		return
	}
	if string(got.Data) != "still here" {
		t.Errorf("got %q", got.Data)
	}
}

func TestAnUnknownModeIsACallerBugNotAPathCondition(t *testing.T) {
	r, _ := openRoot(t)
	_, err := r.Write("a.txt", []byte("x"), fileroot.WriteMode("clobber"), "")
	if err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if c := fileroot.CodeOf(err); c != "" {
		t.Errorf("an unknown mode was reported as %q, which tells a model the wrong thing", c)
	}
}
