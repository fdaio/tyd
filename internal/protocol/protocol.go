package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const MaxFrame = 1 << 20

type Type string

const (
	TypeCreate  Type = "create"
	TypeList    Type = "list"
	TypeAttach  Type = "attach"
	TypeWatch   Type = "watch"
	TypeDetach  Type = "detach"
	TypeWrite   Type = "write"
	TypeRead    Type = "read"
	TypeSend    Type = "send"
	TypeResize  Type = "resize"
	TypeSignal  Type = "signal"
	TypeClose   Type = "close"
	TypeApprove Type = "approve"
	TypeReject  Type = "reject"
	TypeAuth    Type = "auth"
	TypeBound   Type = "bound" // server proves its identity over the relay TLS binding
	TypeStatus  Type = "status"

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
	// MaxBytes returns once this many bytes have accumulated after the
	// cursor, cut back to a rune boundary.
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
