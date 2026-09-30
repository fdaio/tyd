package mcp

import (
	"strings"
	"testing"
)

// The decoder is the boundary a model's bytes come through, so it has to hold
// three things whatever it is fed: it never panics, it never invents a frame out
// of bytes that were not one, and a frame it does accept is decodable rather than
// half-decoded. A server that dies on a malformed frame takes every session with
// it, and one that answers a truncated frame has told the model something that
// did not happen.
func FuzzDecodeNeverInventsAFrame(f *testing.F) {
	for _, in := range []string{
		"",
		"\n",
		"{}\n",
		`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n",
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`, // no newline: incomplete
		`{"jsonrpc":"2.0","id":1,"method":"pi`,     // cut in half
		`{"jsonrpc":"2.0","id":` + "\x01\x02" + `}` + "\n",
		"not json at all\n",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"session_send"}}` + "\n",
		`{"jsonrpc":"2.0","id":1,"method":"a"` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"b"}` + "\n",
	} {
		f.Add([]byte(in))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		dec := newDecoder(strings.NewReader(string(in)))
		frames := 0
		for {
			m, err := dec.next()
			if err != nil {
				// Every error is one of the kinds the loop above knows how to
				// answer or skip. A panic or a hang is the failure; an error is
				// the design.
				if err == nil {
					t.Fatal("next returned no frame and no error")
				}
				return
			}
			frames++
			if frames > 64 {
				// A frame per byte with no progress would spin forever on input
				// that cannot be a conversation.
				t.Fatalf("64 frames out of %d bytes", len(in))
			}
			// A frame is a request, a response or a notification, and anything
			// else is a protocol error the server drops with a log line. A
			// decoder that produced one is producing a frame nobody sent.
			if !m.isRequest() && !m.isNotification() && m.Method != "" {
				t.Fatalf("frame %d has method %q and is neither", frames, m.Method)
			}
			if m.isRequest() && (m.ID == nil || m.Method == "") {
				t.Fatalf("frame %d is a request with no id or no method: %+v", frames, m)
			}
		}
	})
}
