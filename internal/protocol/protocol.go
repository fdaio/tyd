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
	TypeCreate Type = "create"
	TypeList   Type = "list"
	TypeAttach Type = "attach"
	TypeDetach Type = "detach"
	TypeWrite  Type = "write"
	TypeResize Type = "resize"
	TypeSignal Type = "signal"
	TypeClose  Type = "close"
	TypeAuth   Type = "auth"

	TypeChallenge Type = "challenge"
	TypeOK        Type = "ok"
	TypeError     Type = "error"
	TypeOutput    Type = "output"
	TypeAttached  Type = "attached"
	TypeDetached  Type = "detached"
	TypeClosed    Type = "closed"
	TypeExit      Type = "exit"
	TypeSessions  Type = "sessions"
)

type Frame struct {
	Type      Type   `json:"type"`
	ID        string `json:"id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Error     string `json:"error,omitempty"`

	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`

	Data      []byte `json:"data,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
	Signal    string `json:"signal,omitempty"`
	Shell     string `json:"shell,omitempty"`
	Cwd       string `json:"cwd,omitempty"`

	Session  *SessionInfo  `json:"session,omitempty"`
	Sessions []SessionInfo `json:"sessions,omitempty"`
	ExitCode int           `json:"exit_code,omitempty"`
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
