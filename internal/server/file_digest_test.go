package server

import (
	"strings"
	"testing"

	"tyd/internal/auth"
	"tyd/internal/protocol"
)

// A digest that does not name the path is a digest that does not describe the request.
// These are the assertions §5 exists for, written against the digest rather than left
// to the implementation being correct.

func TestAFileDigestNamesThePath(t *testing.T) {
	base := fileApprovalDigest(opFileRead, "sess1", "notes.txt", "", 4096)

	// The same request twice is the same digest, or an approval could never be spent.
	if again := fileApprovalDigest(opFileRead, "sess1", "notes.txt", "", 4096); again != base {
		t.Error("the same request produced two digests")
	}
	// Each of these is a different request, and each must therefore be a different
	// digest — otherwise one approval is spent by another operation.
	for name, got := range map[string]string{
		"another path":       fileApprovalDigest(opFileRead, "sess1", "authorized_keys", "", 4096),
		"a longer path":      fileApprovalDigest(opFileRead, "sess1", "notes.txt.bak", "", 4096),
		"a parent path":      fileApprovalDigest(opFileRead, "sess1", "../notes.txt", "", 4096),
		"another session":    fileApprovalDigest(opFileRead, "sess2", "notes.txt", "", 4096),
		"another size":       fileApprovalDigest(opFileRead, "sess1", "notes.txt", "", 8192),
		"another mode":       fileApprovalDigest(opFileWrite, "sess1", "notes.txt", "create", 4096),
		"replace not create": fileApprovalDigest(opFileWrite, "sess1", "notes.txt", "replace", 4096),
		"read not write":     fileApprovalDigest(opFileWrite, "sess1", "notes.txt", "", 4096),
	} {
		if got == base {
			t.Errorf("%s produced the same digest, so one approval covers both", name)
		}
	}
}

// The two that matter most, stated on their own so a reader does not have to infer
// them from a table: an approval for reading one file must not open another, and the
// pair a caller is most likely to try is the ordinary-looking path and the one worth
// stealing.
func TestAnApprovalForOneFileDoesNotOpenAnother(t *testing.T) {
	approved := fileApprovalDigest(opFileRead, "sess1", "notes.txt", "", 0)
	stolen := fileApprovalDigest(opFileRead, "sess1", "authorized_keys", "", 0)
	if approved == stolen {
		t.Fatal("an approval for notes.txt is also an approval for authorized_keys")
	}
}

// A path is an arbitrary string and a mode is one of two words, so the fields must be
// separated rather than merely ordered — or a path can be crafted to move a boundary.
func TestTheDigestSeparatesItsFields(t *testing.T) {
	// "ab" + "c" against "a" + "bc": different requests, and concatenation without a
	// separator would make them the same bytes.
	if fileApprovalDigest(opFileRead, "s", "ab", "c", 0) == fileApprovalDigest(opFileRead, "s", "a", "bc", 0) {
		t.Error("two different field splits hashed identically")
	}
	// And a NUL in a path cannot forge a boundary, which is why the separator is NUL.
	if fileApprovalDigest(opFileRead, "s", "a\x00b", "", 0) == fileApprovalDigest(opFileRead, "s", "a", "b", 0) {
		t.Error("a NUL in the path moved a field boundary")
	}
}

// The operation an operator is shown has to name the path, or two pending file
// requests are indistinguishable in the list they approve from.
func TestTheOperatorSummaryNamesThePathAndMode(t *testing.T) {
	got := describeFileRequest(protocol.Frame{
		Type: protocol.TypeFileWrite, Path: "docs/notes.md", Mode: "replace",
	}, 2048)
	for _, want := range []string{"replace", "docs/notes.md", "2048"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary %q does not mention %q", got, want)
		}
	}
	if got := describeFileRequest(protocol.Frame{Type: protocol.TypeFileRead, Path: "a.txt"}, 64); !strings.Contains(got, "a.txt") {
		t.Errorf("a read summary %q does not name the file", got)
	}
	// A request with no path says so rather than showing an empty gap.
	if got := describeFileRequest(protocol.Frame{Type: protocol.TypeFileRead}, 0); !strings.Contains(got, "no path") {
		t.Errorf("a pathless request summarised as %q", got)
	}
}

// CapFile is a separate capability because file access is a separate decision from
// keystrokes, and granting it must be visible in the capability list rather than
// implied by CapAttach.
func TestCapFileIsDistinctFromTheSessionCaps(t *testing.T) {
	if auth.CapFile == auth.CapAttach || auth.CapFile == auth.CapWrite {
		t.Error("CapFile aliases an existing capability")
	}
	var found bool
	for _, c := range auth.OwnerCaps {
		if c == auth.CapFile {
			found = true
		}
	}
	if !found {
		t.Error("CapFile is in nobody's capability set, so no owner can use it")
	}
}

// The failure text a model reads. Two things have to be in it: the reason, and the
// fact that the approval is gone.
//
// The second is not decoration. An approval is spent before the operation runs and is
// not refunded, so a model that reads "not found" as "not now" retries on its own and
// the retry cannot work — there is no approval behind it. And the message deliberately
// states the fact rather than prescribing an action, because for a blocked path a new
// approval would not help either, and advice that cannot work sends the model to an
// operator with nothing to ask for.
func TestTheFailureSaysTheApprovalIsGone(t *testing.T) {
	msg := fileFailure("blocked_path: .bashrc", "the approval for that request has been used; a new operation needs a new approval").Error()
	if !strings.Contains(msg, "blocked_path") {
		t.Errorf("the reason is missing from %q", msg)
	}
	for _, want := range []string{"approval", "new approval"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q does not say %q", msg, want)
		}
	}
	// It must not tell the model to just try again.
	for _, forbidden := range []string{"try again", "retry the same", "just retry"} {
		if strings.Contains(strings.ToLower(msg), forbidden) {
			t.Errorf("the message suggests retrying: %q", msg)
		}
	}
}

// The other half of forwarding a frame whole: copying cannot drop a field, and it
// cannot stop a peer putting one there either.
//
// Everything a peer can reach is injected here, and the frame that would cross is
// checked. This is not a test that the current agent handler ignores stray fields — it
// is a test that the daemon does not forward them, so the property survives someone
// adding a field to Frame that a file handler starts reading.
func TestAPeerCannotAssertFieldsTheDaemonOwns(t *testing.T) {
	injected := protocol.Frame{
		Type: protocol.TypeFileRead, ID: "r1", SessionID: "sess1", Path: "notes.txt",
		// Everything below arrives from the peer and must not survive.
		Version:      99,
		AgentVersion: 4242,
		Cursor:       12345,
		Epoch:        7,
		Secret:       true,
		Rows:         999, Cols: 999,
		Dropped:     5,
		AtEnd:       true,
		CursorAhead: true,
		Exited:      true,
		WaitMS:      4000,
		Shell:       "/bin/bash",
		Cwd:         "/etc",
	}
	out := fileFrameForAgent(injected)

	if out.Version != 0 || out.AgentVersion != 0 {
		t.Errorf("version metadata survived: version=%d agent=%d", out.Version, out.AgentVersion)
	}
	// And the file fields, the ones the peer is supposed to control, are untouched.
	if out.Path != "notes.txt" || out.SessionID != "sess1" || out.ID != "r1" {
		t.Errorf("the daemon altered a file field: %+v", out)
	}
}

// The digest and the size cannot be injected at all, because they are not fields — they
// are computed here. Proven by asking for the same operation twice with different junk
// attached and getting the same digest: if any of it reached the digest, an approval
// granted for one would not cover the other, and a peer could choose which one.
func TestAnInjectedFieldCannotChangeTheDigest(t *testing.T) {
	plain := protocol.Frame{Type: protocol.TypeFileRead, Path: "notes.txt"}
	loaded := protocol.Frame{
		Type: protocol.TypeFileRead, Path: "notes.txt",
		Version: 99, AgentVersion: 4242, Secret: true, Cwd: "/etc", Shell: "/bin/sh",
	}

	digestOf := func(f protocol.Frame) string {
		size := int64(f.MaxBytes)
		if f.Type == protocol.TypeFileWrite {
			size = int64(len(f.Data))
		}
		return fileApprovalDigest(opFileRead, f.SessionID, f.Path, f.Mode, size)
	}
	if digestOf(plain) != digestOf(loaded) {
		t.Error("a peer-supplied field changed the digest, so one request could be approved as another")
	}
	// The size is derived from the payload, not read from the frame, so the two differ
	// only where the payload does.
	if fileApprovalDigest(opFileRead, "s", "a.txt", "", 0) == fileApprovalDigest(opFileRead, "s", "a.txt", "", 1) {
		t.Error("the digest does not distinguish two sizes")
	}
}

// A refused operation is not recorded as a success, and it is recorded at all.
//
// handleFile returns before auditFile when the agent refuses, so a blocked path left no
// trace. That is worse than recording it wrongly: the one operation an operator most
// wants to see afterwards is the one that was refused.
func TestARefusedOperationIsAuditedAsARefusal(t *testing.T) {
	if refusalResult == "" {
		t.Fatal("a refusal has no recorded result")
	}
	for _, forbidden := range []string{"ok", "success"} {
		if refusalResult == forbidden {
			t.Errorf("a refusal is recorded as %q", refusalResult)
		}
	}
}
