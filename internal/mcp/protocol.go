package mcp

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// wireError is a JSON-RPC error object. A protocol-level failure only: a tool
// that ran and failed answers with a result and isError instead.
type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *wireError) Error() string { return e.Message }

// JSON-RPC error codes. The range is fixed by the specification.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	// codeCancelled is the reserved code for a request the client withdrew.
	codeCancelled = -32800
)

// protocolVersion is what this server speaks. The list is newest first, and
// negotiation answers with the client's version when it is one of them.
const protocolVersion = "2025-06-18"

var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// jsonRPCVersion is the only value the jsonrpc field may hold.
const jsonRPCVersion = "2.0"

// message is any frame on the wire: a request, a response or a notification.
// A frame with an id is a request or a response; without one it is a
// notification.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *wireError      `json:"error,omitempty"`
}

// isRequest reports whether the frame expects a reply.
func (m message) isRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// isNotification reports whether the frame is one way.
func (m message) isNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// negotiateVersion answers with the client's version when this server speaks it,
// and with the newest version it does speak otherwise. A client that cannot
// handle the answer disconnects, which is the specified outcome.
func negotiateVersion(requested string) string {
	for _, v := range supportedVersions {
		if v == requested {
			return v
		}
	}
	return protocolVersion
}

// callParams is the tools/call parameter object.
type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// cancelledParams is the notifications/cancelled parameter object. The id is
// the request being cancelled, which is why it keeps its JSON type: a client may
// send it as a string or a number.
type cancelledParams struct {
	RequestID json.RawMessage `json:"requestId"`
	Reason    string          `json:"reason,omitempty"`
}

// toolResult is the tools/call result. StructuredContent is repeated as a text
// block for clients that predate it, which the specification asks for.
type toolResult struct {
	Content           []contentBlock `json:"content"`
	StructuredContent any            `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// annotations describe a tool for a client that shows it to a person. They are
// hints, and a client must not trust them; the boundary is the daemon's
// capability check, not this field.
type annotations struct {
	// ReadOnlyHint says the tool changes nothing on the target.
	ReadOnlyHint bool `json:"readOnlyHint,omitempty"`
	// DestructiveHint says the tool can end a session or interrupt work.
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	// IdempotentHint says calling it twice is the same as calling it once.
	IdempotentHint bool `json:"idempotentHint,omitempty"`
	// OpenWorldHint says the tool acts on something outside the MCP server.
	OpenWorldHint bool `json:"openWorldHint,omitempty"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations *annotations   `json:"annotations,omitempty"`
}

// args is the argument object of a tool call. A named type so the field readers
// below can be methods.
//
// A field of the wrong type is a usage error rather than a silently ignored
// value: a model that passed a number where a string belongs has to be told, or
// it will try the same call again.
type args map[string]any

// str reads a string field.
func (a args) str(name string) (string, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalidParams("%s must be a string", name)
	}
	return s, nil
}

func (a args) boolean(name string, def bool) (bool, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, invalidParams("%s must be true or false", name)
	}
	return b, nil
}

func (a args) uint32(name string) (uint32, bool, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return 0, false, nil
	}
	n, ok := v.(float64)
	if !ok {
		return 0, false, invalidParams("%s must be a number", name)
	}
	if n < 0 || n != float64(int64(n)) {
		return 0, false, invalidParams("%s must be a whole number of milliseconds or bytes", name)
	}
	return uint32(n), true, nil
}

func invalidParams(format string, args ...any) error {
	return &wireError{Code: codeInvalidParams, Message: fmt.Sprintf(format, args...)}
}

// waitArg is the shared shape of the read and send wait options.
func waitArg(v any) (Wait, error) {
	var w Wait
	if v == nil {
		return w, nil
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return w, invalidParams("wait must be an object with match, idle_ms, wait_ms")
	}
	obj := args(raw)
	var err error
	if w.Match, err = obj.str("match"); err != nil {
		return w, err
	}
	for _, f := range []struct {
		name string
		dst  *uint32
	}{{"idle_ms", &w.IdleMS}, {"max_bytes", &w.MaxBytes}, {"wait_ms", &w.WaitMS}} {
		n, ok, err := obj.uint32(f.name)
		if err != nil {
			return w, err
		}
		if ok {
			*f.dst = n
		}
	}
	return w, nil
}

// uint reads a cursor-like field. A cursor is a byte offset, so it must not
// arrive as a negative or fractional number.
func (a args) uint(name string) (uint64, bool, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return 0, false, nil
	}
	switch n := v.(type) {
	case float64:
		if n < 0 || n != float64(int64(n)) {
			return 0, false, invalidParams("%s must be a whole number of bytes", name)
		}
		return uint64(n), true, nil
	case string:
		p, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			return 0, false, invalidParams("%s must be a byte offset, for example %q", name, "1024")
		}
		return p, true, nil
	default:
		return 0, false, invalidParams("%s must be a byte offset, for example %q", name, "1024")
	}
}

// has reports whether the caller supplied a field at all, which is different from
// supplying it empty. The distinction matters where absent means "today's
// behaviour" and empty means "a mistake".
// stringOr returns a string argument, or def when it is absent. For an argument that
// is optional and has no meaning as an empty string, so the two are the same thing.
func (a args) stringOr(name, def string) string {
	v, err := a.str(name)
	if err != nil {
		return def
	}
	return v
}

func (a args) has(name string) bool {
	_, ok := a[name]
	return ok
}

// stringList reads a field that is either one string or a list of them, so a caller
// can say `peers: "all"` or `peers: ["a","b"]` without the schema carrying a union.
func (a args) stringList(name string) ([]string, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, invalidParams("%s must be strings", name)
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return t, nil
	default:
		return nil, invalidParams("%s must be a string or a list of strings", name)
	}
}
