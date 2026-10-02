package live

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tyd/internal/fileroot"
	"tyd/internal/protocol"
)

// oneFileOp sends one file request to an agent over a socket and returns the single
// reply. It goes through agent.handle rather than calling the handler directly, so
// the dispatch and the frame round trip are covered too — and it stays in this
// process, which is what "one hop, the agent's own fixture" has to mean.
func oneFileOp(t *testing.T, a *agent, req protocol.Frame) protocol.Frame {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.handle(server)
	}()
	if err := protocol.WriteFrame(client, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := protocol.ReadFrame(client)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	_ = client.Close()
	<-done
	return reply
}

// agentWithRoot builds an agent whose only capability is a file ceiling.
func agentWithRoot(t *testing.T, dir string) *agent {
	t.Helper()
	a := &agent{dir: t.TempDir()}
	if dir == "" {
		return a
	}
	root, err := fileroot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	a.fileRoot = root
	return a
}

func rootDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The whole round trip: a request arrives on a socket, the agent answers with the
// file's bytes and a digest of the whole file.
func TestAFileReadCrossesTheSocketAndComesBack(t *testing.T) {
	dir := rootDir(t, map[string]string{"notes.txt": "hello from the agent"})
	reply := oneFileOp(t, agentWithRoot(t, dir), protocol.Frame{
		Type: protocol.TypeFileRead, Path: "notes.txt",
	})
	if reply.Type != protocol.TypeFileResult {
		t.Fatalf("reply type %q, want file_result", reply.Type)
	}
	if reply.Error != "" {
		t.Fatalf("error %q", reply.Error)
	}
	if string(reply.Data) != "hello from the agent" {
		t.Errorf("bytes %q", reply.Data)
	}
	if reply.Size != int64(len("hello from the agent")) {
		t.Errorf("size %d", reply.Size)
	}
	if reply.SHA256 == "" {
		t.Error("no digest, so a later write could not use it as expected_sha256")
	}
	if reply.MTimeMS == 0 {
		t.Error("no mtime")
	}
}

// A write, then a read of what landed — through the same socket, so the reply
// fields are the ones a caller would act on.
func TestAFileWriteCrossesTheSocket(t *testing.T) {
	dir := rootDir(t, nil)
	a := agentWithRoot(t, dir)

	reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileWrite, Path: "made.txt", Mode: "create",
		Data: []byte("written through the agent"),
	})
	if reply.Error != "" {
		t.Fatalf("error %q", reply.Error)
	}
	if reply.Bytes != len("written through the agent") {
		t.Errorf("bytes %d", reply.Bytes)
	}
	if !reply.Created {
		t.Error("created not reported")
	}
	// The content must not be echoed back: the caller sent it.
	if len(reply.Data) != 0 {
		t.Errorf("the reply echoed the content: %q", reply.Data)
	}

	got := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: "made.txt"})
	if string(got.Data) != "written through the agent" {
		t.Errorf("read back %q", got.Data)
	}
	// The digest of a write is the digest of what was written, so it can be used as
	// the next expected_sha256.
	if got.SHA256 != reply.SHA256 {
		t.Errorf("write digest %q and read digest %q disagree", reply.SHA256, got.SHA256)
	}
}

// No --file-root means the operations do not exist. The answer must be
// `unavailable`, not `not_found`: "there is no filesystem here" and "that file is
// not there" are different, and conflating them would tell a caller it may retry.
func TestNoRootMeansTheOperationsDoNotExist(t *testing.T) {
	dir := rootDir(t, map[string]string{"a.txt": "content"})
	for _, req := range []protocol.Frame{
		{Type: protocol.TypeFileRead, Path: "a.txt"},
		{Type: protocol.TypeFileWrite, Path: "b.txt", Mode: "create", Data: []byte("x")},
	} {
		reply := oneFileOp(t, agentWithRoot(t, ""), req)
		if reply.Error == "" {
			t.Fatalf("%s was answered with no error and no root configured", req.Type)
		}
		if !strings.Contains(reply.Error, string(fileroot.CodeUnavailable)) {
			t.Errorf("%s gave %q, want %s", req.Type, reply.Error, fileroot.CodeUnavailable)
		}
		if strings.Contains(reply.Error, "not_found") {
			t.Errorf("%s reported a missing file when no root exists at all", req.Type)
		}
	}
	// And nothing was written, since the directory was never consulted.
	if _, err := os.Stat(filepath.Join(dir, "b.txt")); err == nil {
		t.Error("a write landed with no root configured")
	}
}

// The ceiling may be narrowed by a claim and never widened. The refusal has to come
// from somewhere that cannot be argued with, so this asserts the sub-root was
// derived by os.Root rather than by a prefix test: the sibling directory shares a
// textual prefix with the root and is still outside it.
func TestTheAgentNarrowsButNeverWidens(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	for _, d := range []string{filepath.Join(root, "sub"), filepath.Join(base, "root-evil")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "sub/inside.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.txt"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "root-evil/stolen.txt"), []byte("stolen"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := agentWithRoot(t, root)

	// Narrowing works.
	reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileRead, Path: "inside.txt", Root: "sub",
	})
	if reply.Error != "" {
		t.Fatalf("narrowing failed: %q", reply.Error)
	}
	if string(reply.Data) != "inside" {
		t.Errorf("got %q", reply.Data)
	}
	// And what is above the narrowed root is not reachable through it.
	if reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileRead, Path: "../outside.txt", Root: "sub",
	}); reply.Error == "" {
		t.Error("a read escaped a narrowed root")
	}

	for _, claim := range []string{"..", "../root-evil", "/etc", "/"} {
		reply := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: "inside.txt", Root: claim})
		if reply.Error == "" {
			t.Errorf("claim %q was accepted, so it widened the ceiling", claim)
		}
	}
	if _, err := os.Stat(filepath.Join(base, "root-evil/stolen.txt")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(base, "root-evil/stolen.txt")); err != nil || string(b) != "stolen" {
		t.Error("the file outside the ceiling was disturbed")
	}
}

// A field that is silently dropped is the failure mode §10 is about, so each field
// that changes behaviour is asserted to have arrived by checking the effect it has.
func TestEveryFieldArrivesAndIsUsed(t *testing.T) {
	dir := rootDir(t, map[string]string{"big.txt": strings.Repeat("x", 500), "f.txt": "v1"})
	a := agentWithRoot(t, dir)

	// MaxBytes: a smaller cap truncates, and the reply says so.
	reply := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: "big.txt", MaxBytes: 100})
	if len(reply.Data) != 100 || !reply.Truncated {
		t.Errorf("max_bytes did not arrive: %d bytes truncated=%v", len(reply.Data), reply.Truncated)
	}
	// Offset: a read starts where it was told to.
	reply = oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: "f.txt", Offset: 1})
	if string(reply.Data) != "v1"[1:] {
		t.Errorf("offset did not arrive: %q", reply.Data)
	}
	// Mode: create then replace are different operations.
	if reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileWrite, Path: "f.txt", Mode: "create", Data: []byte("v2"),
	}); reply.Error == "" {
		t.Error("mode=create overwrote an existing file")
	}
	if reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileWrite, Path: "f.txt", Mode: "replace", Data: []byte("v2"),
	}); reply.Error != "" {
		t.Errorf("mode=replace failed: %q", reply.Error)
	}
	// ExpectedSHA: a stale one is refused.
	if reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileWrite, Path: "f.txt", Mode: "replace",
		Data: []byte("v3"), ExpectedSHA: strings.Repeat("0", 64),
	}); reply.Error == "" {
		t.Error("expected_sha256 did not arrive, so a stale guard was accepted")
	}
}

// A field that is nonsense is refused rather than ignored, because an ignored field
// is how a forwarded field goes missing without anyone noticing.
func TestTheAgentRefusesFieldsThatDoNotApply(t *testing.T) {
	dir := rootDir(t, map[string]string{"a.txt": "x"})
	a := agentWithRoot(t, dir)
	for name, req := range map[string]protocol.Frame{
		"a mode on a read":     {Type: protocol.TypeFileRead, Path: "a.txt", Mode: "create"},
		"a write with no mode": {Type: protocol.TypeFileWrite, Path: "b.txt", Data: []byte("x")},
		"an unknown mode":      {Type: protocol.TypeFileWrite, Path: "b.txt", Mode: "clobber", Data: []byte("x")},
		"a negative offset":    {Type: protocol.TypeFileRead, Path: "a.txt", Offset: -1},
		"an offset on a write": {Type: protocol.TypeFileWrite, Path: "b.txt", Mode: "create", Offset: 4, Data: []byte("x")},
		"max_bytes over cap":   {Type: protocol.TypeFileRead, Path: "a.txt", MaxBytes: fileroot.MaxReadBytes + 1},
	} {
		reply := oneFileOp(t, a, req)
		if reply.Error == "" {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "b.txt")); err == nil {
		t.Error("a refused write still created the file")
	}
}

// The agent decides the sensitive-path list, not the sender.
//
// The two lists are deliberately different sizes, so this pins the asymmetry rather
// than just the block list. A read cannot become code execution, and a deny list long
// enough to be thorough starts refusing files a model legitimately needs — which is
// how a deny list gets turned off wholesale. Making the two identical would look like
// tidying and would be a regression.
func TestTheAgentDecidesSensitivePaths(t *testing.T) {
	dir := rootDir(t, map[string]string{
		".bashrc":          "echo pwned\n",
		".ssh/id_rsa":      "PRIVATE KEY",
		".gnupg/secring":   "SECRET",
		".aws/credentials": "AKIA...",
	})
	a := agentWithRoot(t, dir)

	// Refused both ways: these hold the secrets themselves.
	for _, p := range []string{".ssh/id_rsa", ".gnupg/secring", ".aws/credentials"} {
		if reply := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: p}); reply.Error == "" {
			t.Errorf("read of %s was allowed", p)
		}
		if reply := oneFileOp(t, a, protocol.Frame{
			Type: protocol.TypeFileWrite, Path: p, Mode: "create", Data: []byte("x"),
		}); reply.Error == "" {
			t.Errorf("write of %s was allowed", p)
		}
	}
	// Write-only: a startup file or a hook turns a write into code execution.
	for _, p := range []string{".bashrc", ".profile", ".zshrc", ".git/hooks/pre-commit"} {
		if reply := oneFileOp(t, a, protocol.Frame{
			Type: protocol.TypeFileWrite, Path: p, Mode: "create", Data: []byte("x"),
		}); reply.Error == "" {
			t.Errorf("write of %s was allowed", p)
		}
	}
	// And reading one is allowed, on purpose. Asserted so the asymmetry is a
	// recorded decision rather than an accident someone tidies away.
	if reply := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: ".bashrc"}); reply.Error != "" {
		t.Errorf("reading a startup file was refused (%q); the read list is meant to be narrower", reply.Error)
	}

	if b, err := os.ReadFile(filepath.Join(dir, ".bashrc")); err != nil || string(b) != "echo pwned\n" {
		t.Error("a refused write changed the file anyway")
	}
}

// An error is text a model reads, so it must not carry an absolute path.
func TestRepliesCarryNoAbsolutePath(t *testing.T) {
	base := t.TempDir()
	dir := rootDir(t, nil)
	a := agentWithRoot(t, dir)
	for _, req := range []protocol.Frame{
		{Type: protocol.TypeFileRead, Path: "../../etc/passwd"},
		{Type: protocol.TypeFileRead, Path: "/etc/passwd"},
		{Type: protocol.TypeFileRead, Path: "nope.txt"},
	} {
		reply := oneFileOp(t, a, req)
		if reply.Error == "" {
			t.Fatalf("%+v was allowed", req)
		}
		if strings.Contains(reply.Error, base) || strings.Contains(reply.Error, dir) {
			t.Errorf("the reply leaks an absolute path: %q", reply.Error)
		}
	}
}

// Two operations in a row on the same agent, so a narrowed root opened for one call
// does not leak into the next.
func TestEachCallGetsItsOwnRoot(t *testing.T) {
	dir := rootDir(t, map[string]string{"sub/inside.txt": "inside", "top.txt": "top"})
	a := agentWithRoot(t, dir)

	for i := 0; i < 20; i++ {
		if reply := oneFileOp(t, a, protocol.Frame{
			Type: protocol.TypeFileRead, Path: "inside.txt", Root: "sub",
		}); reply.Error != "" {
			t.Fatalf("iteration %d: %q", i, reply.Error)
		}
		if reply := oneFileOp(t, a, protocol.Frame{Type: protocol.TypeFileRead, Path: "top.txt"}); reply.Error != "" {
			t.Fatalf("iteration %d: %q", i, reply.Error)
		}
	}
}

// The reply is one frame per request, whatever happens, so a caller that reads one
// reply always gets one.
func TestExactlyOneReplyPerRequest(t *testing.T) {
	dir := rootDir(t, map[string]string{"a.txt": "x"})
	a := agentWithRoot(t, dir)
	client, server := net.Pipe()
	go a.handle(server)
	if err := protocol.WriteFrame(client, protocol.Frame{Type: protocol.TypeFileRead, Path: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ReadFrame(client); err != nil {
		t.Fatal(err)
	}
	// A second read must not produce a second reply. net.Pipe is unbuffered, so a
	// second frame would arrive immediately; blocking here is the assertion, and
	// closing the client ends it.
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := protocol.ReadFrame(client); err == nil {
		t.Error("two replies for one request")
	}
	_ = client.Close()
}

// A read big enough that its reply does not fit in one frame used to be answered
// with a closed connection and no error at all: the page was capped by the library,
// the reply was not capped by the wire, the encoder refused the frame, and the error
// had nowhere to go. So this asks for the largest thing the feature allows and
// requires bytes back.
//
// Every part of this was decided against the numbers rather than by feel: the payload
// is base64 in a JSON frame, so the ceiling is three quarters of what is left after the
// metadata, not three quarters of MaxFrame.
func TestTheLargestAllowedReadComesBack(t *testing.T) {
	dir := rootDir(t, nil)
	body := make([]byte, protocol.MaxDataBytes)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	if err := os.WriteFile(filepath.Join(dir, "max.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	a := agentWithRoot(t, dir)

	// At the wire ceiling: answered, with every byte.
	reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileRead, Path: "max.bin", MaxBytes: protocol.MaxDataBytes,
	})
	if reply.Error != "" {
		t.Fatalf("a read at the wire ceiling failed: %q", reply.Error)
	}
	if len(reply.Data) != protocol.MaxDataBytes {
		t.Errorf("got %d bytes, want %d", len(reply.Data), protocol.MaxDataBytes)
	}
	if !bytes.Equal(reply.Data, body) {
		t.Error("the page came back altered")
	}

	// Above it: refused with a code and a number, not silence.
	reply = oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileRead, Path: "max.bin", MaxBytes: protocol.MaxDataBytes + 1,
	})
	if reply.Error == "" {
		t.Fatal("a read above the wire ceiling was answered rather than refused")
	}
	if !strings.Contains(reply.Error, string(fileroot.CodeTooLarge)) ||
		!strings.Contains(reply.Error, "780288") {
		t.Errorf("error %q does not name too_large or the number", reply.Error)
	}
}

// The library's own ceilings are above the wire, which is why there are two numbers and
// why the agent checks both. Asserted here because this is where both are visible.
func TestTheWireCeilingSitsBelowTheLibraryCeilings(t *testing.T) {
	if protocol.MaxDataBytes >= fileroot.MaxReadBytes {
		t.Errorf("the wire ceiling %d is not below the read ceiling %d, so one of the two checks is dead code",
			protocol.MaxDataBytes, fileroot.MaxReadBytes)
	}
	if protocol.MaxDataBytes >= fileroot.MaxWriteBytes {
		t.Errorf("the wire ceiling %d is not below the write ceiling %d", protocol.MaxDataBytes, fileroot.MaxWriteBytes)
	}
}

// The reply has to carry back the ID it was asked with, on every path. A caller that
// cannot match a reply to its request cannot multiplex, and a file read is the kind
// of call worth overlapping with something else. Nothing else in this file checks it,
// because every other assertion here is about one reply whose ID nothing reads.
func TestTheReplyEchoesTheRequestID(t *testing.T) {
	dir := rootDir(t, map[string]string{"a.txt": "x"})
	a := agentWithRoot(t, dir)
	for _, id := range []string{"req-1", "", strings.Repeat("i", 200)} {
		reply := oneFileOp(t, a, protocol.Frame{
			Type: protocol.TypeFileRead, ID: id, Path: "a.txt",
		})
		if reply.ID != id {
			t.Errorf("asked with id %q, reply carried %q", id, reply.ID)
		}
	}
	// And on the failure path, which is the one that matters: an error the caller
	// cannot match is an error it has to wait out a timeout to attribute.
	reply := oneFileOp(t, a, protocol.Frame{
		Type: protocol.TypeFileRead, ID: "req-2", Path: "missing.txt",
	})
	if reply.ID != "req-2" {
		t.Errorf("the failure reply carried id %q, want req-2", reply.ID)
	}
	if reply.Error == "" {
		t.Error("the missing-file read was not refused")
	}
}
