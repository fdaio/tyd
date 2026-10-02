package live

import (
	"fmt"
	"io"
	"strings"

	"tyd/internal/fileroot"
	"tyd/internal/protocol"
)

// The agent side of the file RPCs.
//
// **Everything here is decided here.** The daemon sends a request; it does not get
// to say what is allowed. That is the #118 lesson — a field forwarded across two
// hops is checked where the resource is — and it is why the root ceiling lives in
// the agent and not in the daemon's configuration.
//
// The operations are refused rather than degraded. No root configured means there is
// no filesystem to offer, and a request that arrives anyway gets `unavailable`,
// which is a different answer from "the file is not there" on purpose.

// fileOps answers one file request on a connection and writes the single reply.
//
// It is a free function so the root it uses is a parameter: the agent owns the
// configured ceiling, and a narrowing claim on the frame selects a sub-root for the
// duration of one call.
func fileOps(ceiling *fileroot.Root, conn io.Writer, f protocol.Frame) {
	reply := protocol.Frame{Type: protocol.TypeFileResult, ID: f.ID}
	if err := serveFile(ceiling, f, &reply); err != nil {
		// The error text is the model's answer, so it carries the code and the
		// root-relative path and nothing else: no absolute path, and never the
		// content.
		reply = protocol.Frame{Type: protocol.TypeFileResult, ID: f.ID, Error: err.Error()}
	}
	if err := protocol.WriteFrame(conn, reply); err != nil {
		// Nothing can be said about it: the channel this would travel on is the frame
		// that just failed. It should be unreachable, because every payload here is
		// bounded by protocol.MaxDataBytes and the reply is a metadata envelope
		// around it — and the first version of this was not bounded, so a large read
		// silently closed the connection instead of answering too_large.
		//
		// So this is a bug if it happens, and the way to find out is a test that asks
		// for the largest thing the feature allows and gets bytes back.
		_ = err
	}
}

// serveFile performs one operation and fills in the reply's result fields. The
// reply is filled in place so an error and a success cannot disagree about the ID.
func serveFile(ceiling *fileroot.Root, f protocol.Frame, reply *protocol.Frame) error {
	root, release, err := resolveRoot(ceiling, f.Root)
	if err != nil {
		return err
	}
	defer release()

	switch f.Type {
	case protocol.TypeFileRead:
		return serveFileRead(root, f, reply)
	case protocol.TypeFileWrite:
		return serveFileWrite(root, f, reply)
	default:
		return fmt.Errorf("unknown file operation %q", f.Type)
	}
}

// resolveRoot returns the root one operation runs against, and a function that
// releases it.
//
// The ceiling is the agent's own. A `root` on the frame may only narrow it, and the
// narrowing is done with os.Root.OpenRoot, so a claim that leaves the ceiling fails
// inside the standard library instead of being compared against a string here.
//
// The sub-root is opened per call and closed with it. Caching it would mean holding
// a descriptor per distinct narrowing for the life of the session, on the strength
// of a claim that arrived on a socket; opening one costs a pair of syscalls and
// leaves nothing behind if the session dies mid-call.
func resolveRoot(ceiling *fileroot.Root, claim string) (*fileroot.Root, func(), error) {
	if ceiling == nil {
		// No --file-root. The tools do not exist, whatever the caller passes.
		return nil, func() {}, fmt.Errorf("%s: no file root is configured", fileroot.CodeUnavailable)
	}
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return ceiling, func() {}, nil
	}
	sub, err := ceiling.Narrow(claim)
	if err != nil {
		return nil, func() {}, err
	}
	return sub, func() { _ = sub.Close() }, nil
}

func serveFileRead(root *fileroot.Root, f protocol.Frame, reply *protocol.Frame) error {
	if f.Offset < 0 {
		return fmt.Errorf("offset must not be negative")
	}
	if f.Mode != "" {
		// A mode on a read is a caller that assembled the wrong frame. Refusing it
		// is better than ignoring it, because ignoring a field is how a forwarded
		// field goes missing without anyone noticing.
		return fmt.Errorf("a read carries no mode")
	}
	// Two ceilings, and the smaller one is the wire. fileroot.MaxReadBytes is what the
	// library will read; protocol.MaxDataBytes is what a frame can carry once the page
	// is base64 and a reply envelope is added. Between them a read cannot be answered,
	// and answering it by dropping the frame leaves the caller with a closed connection
	// and no error at all — so the wire bound is checked here, where it can still be
	// reported as too_large with a number in it.
	if int64(f.MaxBytes) > fileroot.MaxReadBytes {
		return fmt.Errorf("%s: max_bytes %d is above the %d ceiling",
			fileroot.CodeTooLarge, f.MaxBytes, fileroot.MaxReadBytes)
	}
	if int64(f.MaxBytes) > protocol.MaxDataBytes {
		return fmt.Errorf("%s: max_bytes %d is above the %d ceiling of a single reply frame",
			fileroot.CodeTooLarge, f.MaxBytes, protocol.MaxDataBytes)
	}
	res, err := root.Read(f.Path, f.Offset, int(f.MaxBytes))
	if err != nil {
		return err
	}
	reply.Bytes = len(res.Data)
	reply.Size = res.Size
	reply.Truncated = res.Truncated
	reply.SHA256 = res.SHA256
	reply.MTimeMS = res.MTime.UnixMilli()
	// The page travels as raw bytes. It is not cleaned, escaped, or line-disciplined:
	// a file read is not a terminal read, and a model asking for bytes gets bytes.
	reply.Data = res.Data
	return nil
}

func serveFileWrite(root *fileroot.Root, f protocol.Frame, reply *protocol.Frame) error {
	var mode fileroot.WriteMode
	switch f.Mode {
	case string(fileroot.ModeCreate):
		mode = fileroot.ModeCreate
	case string(fileroot.ModeReplace):
		mode = fileroot.ModeReplace
	case "":
		return fmt.Errorf("a write must say whether it creates or replaces")
	default:
		return fmt.Errorf("unknown write mode %q", f.Mode)
	}
	if len(f.Data) > fileroot.MaxWriteBytes {
		return fmt.Errorf("%s: %d bytes is above the %d ceiling",
			fileroot.CodeTooLarge, len(f.Data), fileroot.MaxWriteBytes)
	}
	if len(f.Data) > protocol.MaxDataBytes {
		// Unreachable in practice: a request this size does not survive the frame
		// encoder, so it never arrives. Kept because the write ceiling and the wire
		// ceiling are separate numbers and only one of them is enforced on this side.
		return fmt.Errorf("%s: %d bytes is above the %d ceiling of a single request frame",
			fileroot.CodeTooLarge, len(f.Data), protocol.MaxDataBytes)
	}
	if f.Offset != 0 {
		return fmt.Errorf("a write does not take an offset")
	}
	res, err := root.Write(f.Path, f.Data, mode, f.ExpectedSHA)
	if err != nil {
		return err
	}
	reply.Bytes = res.Written
	reply.Created = res.Created
	reply.SHA256 = res.SHA256
	reply.Size = int64(len(f.Data))
	// The content is deliberately not echoed. The reply says how many bytes landed
	// and what they hash to; a caller that wants them back has them, because it
	// sent them.
	return nil
}
