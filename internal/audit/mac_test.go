package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTheContentMACNeedsTheKey(t *testing.T) {
	var k, other Key
	copy(k[:], []byte("k"))
	copy(other[:], []byte("j"))
	content := []byte("hunter2")

	mac := k.MAC(KindFileWrite, content)
	if mac == "" {
		t.Fatal("no mac")
	}
	if !k.Verify(KindFileWrite, content, mac) {
		t.Error("the key does not verify its own mac")
	}
	// The whole point: a log reader cannot check a guess.
	if other.Verify(KindFileWrite, content, mac) {
		t.Error("a different key verified the mac, so the log is an offline verifier")
	}
	// And the mac is not a bare digest, or it would be the same thing.
	sum := string(mac)
	if len(sum) != 64 {
		t.Errorf("mac %q is not a hex sha256 length", sum)
	}
}

// A mac from one use must not be presentable as a mac from another, or a record
// could be moved between fields and still verify.
func TestTheMACIsBoundToItsUse(t *testing.T) {
	var k Key
	copy(k[:], []byte("k"))
	content := []byte("same bytes")
	write := k.MAC(KindFileWrite, content)
	read := k.MAC(KindFileRead, content)
	if write == read {
		t.Error("the same content produced the same mac for a read and a write")
	}
	if k.Verify(KindFileRead, content, write) {
		t.Error("a write mac verified as a read mac")
	}
}

func TestTheKeyIsCreatedOnceAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.key")

	k, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key mode %04o, want 0600", mode)
	}
	// A second call reads the same key rather than making a new one, or every record
	// before the restart would stop verifying for no stated reason.
	again, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if again != k {
		t.Error("the key changed on the second load")
	}
}

// A key others can read is not a key, and continuing would produce records that look
// authenticated and are not. So this is an error, not a warning.
func TestAKeyReadableByOthersIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	if _, err := LoadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKey(path); err == nil {
			t.Errorf("a key at mode %04o was accepted", mode)
		}
	}
	// Put it back so the deferred cleanup is not fighting the test.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err != nil {
		t.Errorf("a 0600 key was refused: %v", err)
	}
}

func TestAKeyOfTheWrongLengthIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Error("a short key was accepted; padding it would differ from what the operator has")
	}
}

// Two daemons starting at once: exactly one creates the key, and both end up with
// the same one, or they could not verify each other's records.
func TestConcurrentKeyCreationConverges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	var wg sync.WaitGroup
	got := make([]Key, 8)
	errs := make([]error, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = LoadOrCreateKey(path)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := range got {
		if got[i] != got[0] {
			t.Errorf("goroutine %d ended up with a different key", i)
		}
	}
}

// The content must not be in the log. This is the structural claim from §7, so it is
// asserted against a real log rather than against the type.
func TestContentNeverReachesTheLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	canary := "correct-horse-battery-staple-9f3a"
	var k Key
	copy(k[:], []byte("k"))
	f.Log(Event{Kind: KindFileWrite, Path: "secret.txt", Bytes: len(canary), ContentMAC: k.MAC(KindFileWrite, []byte(canary))})
	f.Log(Event{Kind: KindFileRead, Path: "secret.txt", Bytes: len(canary)})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Error("the content reached the audit log")
	}
	// The metadata did, which is what makes the record useful.
	for _, want := range []string{"file_write", "file_read", "secret.txt"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the record is missing %q", want)
		}
	}
}

// A record's new fields are inside the chained payload, so removing one is detected
// like any other tampering.
func TestTheFileFieldsAreInsideTheChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var k Key
	copy(k[:], []byte("k"))
	f.Log(Event{Kind: KindFileWrite, SessionID: "s1", Path: "a.txt", WriteMode: "create", Bytes: 3, ContentMAC: k.MAC(KindFileWrite, []byte("abc"))})
	f.Log(Event{Kind: KindFileWrite, SessionID: "s2", Path: "b.txt", WriteMode: "create", Bytes: 4, ContentMAC: k.MAC(KindFileWrite, []byte("abcd"))})
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokenAt != 0 {
		t.Errorf("a chain written with the file fields does not verify: %s", res.Reason)
	}
	if res.Records != 2 {
		t.Errorf("records %d, want 2", res.Records)
	}

	// Now rewrite a path and confirm the chain notices.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "a.txt", "z.txt", 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokenAt == 0 {
		t.Error("changing a file path did not break the chain")
	}
}
