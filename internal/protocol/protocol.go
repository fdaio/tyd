package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const MaxFrame = 1 << 20

// frameMetadataSlack reserves room in a frame for everything that is not Data.
//
// Derived from a bound that is **enforced** (fileroot.MaxPathLen and MaxRootLen) and
// from the **worst-case encoding** of those bytes.
//
// The second half is the part that is easy to get wrong, and getting it wrong is
// silent. encoding/json escapes `<`, `>` and `&` to six bytes each — `\u003c` — so a
// path of MaxPathLen of them encodes to six times its length, and path plus root claim
// is 12288 bytes before anything else is counted. Measured worst case: 12583.
//
// An earlier version reserved 4096 and derived it from a path filled with `p`, which
// encodes as itself. That test passed, and the write direction still overflowed by 8200
// bytes on any path containing one of the three escaped characters — which are legal in
// filenames and common in generated code. So the test below fills with `<` on purpose:
// a worst-case test written with a character that does not escape is not a worst case.
//
// 16 KiB covers 12583 with room to spare. The price is about 1% of the payload, which
// is cheap against a frame that cannot be sent.
const frameMetadataSlack = 16 << 10

// MaxDataBytes is the largest Data payload a single frame can carry.
//
// Data is JSON, so a byte array becomes base64 and expands by four thirds. The
// payload is therefore three quarters of what is left after the metadata, not of
// MaxFrame — and not even that: three quarters of MaxFrame is 786432, while the
// largest payload that actually fits alongside full-size metadata is 785460. So the
// slack above is what makes the number correct rather than nearly correct.
//
// This is the ceiling that matters in practice, and it is **below** the library's own
// 1 MiB caps on a read and a write. It is also the number a sender must check against,
// because the slack above assumes the path and root bounds are enforced — see
// fileroot.MaxPathLen, which is where they are.
//
// A page between this and MaxReadBytes cannot be
// sent at all: the frame encoder refuses it, and a sender that ignored the error
// would drop the reply on the floor and leave the caller with a closed connection and
// no explanation. So whoever builds a payload uses this, and asks for more than this
// gets `too_large` rather than silence.
const MaxDataBytes = (MaxFrame - frameMetadataSlack) * 3 / 4

type Type string

const (
	TypeCreate Type = "create"
	TypeList   Type = "list"
	TypeAttach Type = "attach"
	TypeWatch  Type = "watch"
	TypeDetach Type = "detach"
	TypeWrite  Type = "write"
	TypeRead   Type = "read"
	TypeSend   Type = "send"
	TypeResize Type = "resize"
	TypeSignal Type = "signal"
	TypeClose  Type = "close"
	// TypeFileRead and TypeFileWrite carry a file operation to the agent that
	// holds the session's directory descriptor. They run to completion, so each is
	// answered by exactly one TypeFileResult.
	//
	// Their presence here is not permission to use them: whether they are
	// registered at all is decided at the far end, from the operator's
	// --file-root. A daemon that offers them against an agent with no root
	// configured gets an error, not a filesystem.
	TypeFileRead  Type = "file_read"
	TypeFileWrite Type = "file_write"
	TypeApprove   Type = "approve"
	TypeReject    Type = "reject"
	TypeAuth      Type = "auth"
	TypeBound     Type = "bound" // server proves its identity over the relay TLS binding
	TypeStatus    Type = "status"

	TypeChallenge   Type = "challenge"
	TypeOK          Type = "ok"
	TypeError       Type = "error"
	TypeOutput      Type = "output"
	TypeAttached    Type = "attached"
	TypeWatching    Type = "watching"
	TypeDetached    Type = "detached"
	TypeClosed      Type = "closed"
	TypeExit        Type = "exit"
	TypeExited      Type = "exited" // shell exited; session is still alive
	TypeSessions    Type = "sessions"
	TypeConnections Type = "connections"
	TypeReadResult  Type = "read_result"
	TypeFileResult  Type = "file_result"
)

type Frame struct {
	Type      Type   `json:"type"`
	ID        string `json:"id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Error     string `json:"error,omitempty"`

	// Version is the handshake protocol version, sent on the challenge and on
	// the auth frame. It is deliberately outside the signature: a peer has to be
	// refused before anything is verified, and a version that was signed could
	// not be checked until after. Absent means a build from before the field
	// existed, which is older than every version there is.
	Version int `json:"version,omitempty"`

	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`

	Data      []byte `json:"data,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
	Signal    string `json:"signal,omitempty"`
	Shell     string `json:"shell,omitempty"`
	Cwd       string `json:"cwd,omitempty"`

	Session     *SessionInfo  `json:"session,omitempty"`
	Sessions    []SessionInfo `json:"sessions,omitempty"`
	Connections []ConnInfo    `json:"connections,omitempty"`
	ExitCode    int           `json:"exit_code,omitempty"`

	Cursor      uint64 `json:"cursor,omitempty"`
	CursorNext  uint64 `json:"cursor_next,omitempty"`
	Dropped     uint64 `json:"dropped,omitempty"`
	AtEnd       bool   `json:"at_end,omitempty"`
	Epoch       uint64 `json:"epoch,omitempty"`
	CursorAhead bool   `json:"cursor_ahead,omitempty"`
	Exited      bool   `json:"exited,omitempty"`
	// WaitMS asks the server to hold a read open until bytes arrive or the
	// wait elapses. Zero means return immediately.
	WaitMS uint32 `json:"wait_ms,omitempty"`
	// IdleMS returns once output has been quiet this long, counted from the
	// last byte after the cursor. The clock only starts once at least one
	// byte has arrived, so a silent session waits for the timeout.
	IdleMS uint32 `json:"idle_ms,omitempty"`
	// Match is an RE2 pattern. The reply returns once the cleaned text
	// matches. The pattern is capped at MaxMatchPattern.
	Match string `json:"match,omitempty"`
	// MaxBytes caps how many bytes come back. On a terminal read it returns once
	// this many bytes have accumulated after the cursor, cut back to a rune
	// boundary; on a file read it caps the page, and the reply says whether it
	// cut it. Same field, because both answer "how much will you take".
	MaxBytes uint32 `json:"max_bytes,omitempty"`
	// Reason says why a read returned.
	Reason string `json:"reason,omitempty"`

	// Secret asks the target to refuse a write unless the terminal is not echoing.
	// It is honoured where the PTY is held, which is the only place the check can
	// be made with nothing between the check and the write. A target that does not
	// understand it ignores it, so a caller that means it must not send without a
	// version it recognises.
	Secret bool `json:"secret,omitempty"`

	// Echo and Icanon are the target terminal's line-discipline bits, reported on
	// a read. They are pointers so an absent field means the target did not report
	// them, which is different from reporting them as off.
	Echo   *bool `json:"echo,omitempty"`
	Icanon *bool `json:"icanon,omitempty"`

	// AgentVersion is what build the agent that sent this frame is. It is not the
	// auth handshake's Version: that one travels daemon to client, and this one
	// travels daemon to agent over a socket with no handshake. It is absent on an
	// agent older than this field, which is what makes a secret write refusable
	// rather than silently ignored.
	AgentVersion int `json:"agent_version,omitempty"`

	// File-operation fields. They travel together across both hops, and each one
	// that arrives changes what the agent does — which is why §10 of the design
	// treats a dropped field as a security bug rather than a missing feature.
	// Nothing here is a pointer: an absent field and a zero field have to mean the
	// same thing to the agent, because there is no way to tell them apart after
	// two hops.
	//
	// Path is always relative to the root. An absolute path is refused by the
	// agent rather than normalised, because the agent cannot know what the sender
	// meant it relative to.
	Path string `json:"path,omitempty"`
	// Root narrows the agent's configured ceiling. It may only narrow: the agent
	// derives the sub-root with os.Root.OpenRoot, so a claim that does not stay
	// inside the ceiling fails inside the standard library rather than being
	// compared against a prefix string here.
	Root string `json:"root,omitempty"`
	// Mode is "create" or "replace" on a write, and empty on a read.
	Mode string `json:"mode,omitempty"`
	// Offset is where a file read starts. It shares MaxBytes with a terminal read:
	// both say how many bytes the caller will take, so one field is enough.
	Offset int64 `json:"offset,omitempty"`
	// ExpectedSHA is the writing side's claim about the content already there. It
	// is the writer's concurrency guard and is deliberately not part of the
	// approval digest: it is not something the operator can see.
	ExpectedSHA string `json:"expected_sha256,omitempty"`

	// FileResult carries what an operation did. Bytes is a count — never the bytes
	// themselves, which travel in Data for a read and are the write's input. SHA256
	// is the digest of the whole file, so a caller can use it as a later
	// expected_sha256. Truncated says the cap cut the page. Created says a create
	// made the file. MTimeMS is a modification time in Unix milliseconds, because a
	// time.Time in a frame is a formatting decision nobody should make twice.
	Bytes      int    `json:"bytes,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Created    bool   `json:"created,omitempty"`
	MTimeMS    int64  `json:"mtime_ms,omitempty"`
	ContentMAC string `json:"content_mac,omitempty"`
}

type ConnInfo struct {
	ID            string `json:"id"`
	Transport     string `json:"transport"`
	LocalAddr     string `json:"local_addr"`
	RemoteAddr    string `json:"remote_addr"`
	TLS           bool   `json:"tls"`
	CertFP        string `json:"cert_fp,omitempty"`
	State         string `json:"state"`
	Principal     string `json:"principal,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	EstablishedAt string `json:"established_at"`
}

type SessionInfo struct {
	ID        string `json:"session_id"`
	Owner     string `json:"owner"`
	User      string `json:"user"`
	PID       int    `json:"pid"`
	CreatedAt string `json:"created_at"`
	State     string `json:"state"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
}

func WriteFrame(w io.Writer, f Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(body) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return Frame{}, fmt.Errorf("invalid frame length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, err
	}
	return f, nil
}
