package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// The output boundary is the last place a result can be repaired, and it is where
// a client decides whether it can keep the connection. A cleaner bug must not be
// able to take every result down with one stray byte, so a frame that is not valid
// UTF-8 is replaced here rather than written as it is.
func TestEncoderRepairsInvalidUTF8(t *testing.T) {
	var out bytes.Buffer
	var log strings.Builder
	enc := newEncoder(&out, newLogger(&log))

	// A string would not do: json.Marshal replaces an invalid byte inside a
	// string with U+FFFD on its own, so a result field can never carry one out.
	// A json.RawMessage is written as it stands, and a reply echoes the client's
	// own id back, so that is where untrusted bytes reach the wire unchanged.
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage("\"\xff\xfeok\""),
	}
	if err := enc.write(payload); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimRight(out.String(), "\n")
	if !utf8.ValidString(line) {
		t.Fatalf("the frame is not valid UTF-8: %q", line)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(line), &back); err != nil {
		t.Fatalf("the frame does not decode once repaired: %v (%q)", err, line)
	}
	if !strings.Contains(line, "ok") {
		t.Fatalf("the id was lost: %q", line)
	}
	// The note says a repair happened and carries none of the content: this is
	// the boundary where the content is least welcome.
	if !strings.Contains(log.String(), "invalid UTF-8") {
		t.Fatalf("the repair was not reported: %q", log.String())
	}
	if strings.Contains(log.String(), "ok") {
		t.Fatalf("the log carried the content: %q", log.String())
	}
	// Valid output is passed through untouched, and says nothing.
	out.Reset()
	log.Reset()
	if err := enc.write(map[string]any{"text": "café é"}); err != nil {
		t.Fatal(err)
	}
	if log.String() != "" {
		t.Fatalf("a valid frame was reported as repaired: %q", log.String())
	}
	if !strings.Contains(out.String(), "café") {
		t.Fatalf("valid text was altered: %q", out.String())
	}
}
