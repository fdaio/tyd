package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errEOF = errors.New("end of input")

// transportMax bounds one frame. A read page is capped at 64KB by the target and
// a send at 2KB by this package, so a frame larger than this is a confused or
// hostile client rather than a slow one.
const transportMax = 8 << 20

// decoder reads newline-delimited JSON frames from one stream.
//
// The buffer is kept across frames: the client may pipeline several requests
// before it reads any answer, and a reader rebuilt per frame would drop
// whatever had already arrived.
type decoder struct {
	br *bufio.Reader
}

func newDecoder(r io.Reader) *decoder {
	return &decoder{br: bufio.NewReaderSize(r, 64<<10)}
}

// frameError is a frame the server cannot read. It carries the JSON-RPC code
// the client is owed, and the id when one could be read, so a bad frame is
// answered instead of silently dropped.
type frameError struct {
	code int
	id   json.RawMessage
	msg  string
}

func (e *frameError) Error() string { return e.msg }

// next returns the next frame. A line that is not a frame is reported as a
// frameError and the caller continues, because a client that writes a stray line
// is still worth serving.
func (d *decoder) next() (message, error) {
	for {
		line, err := d.line()
		if err != nil {
			return message{}, err
		}
		if len(trimSpace(line)) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			return message{}, &frameError{code: codeParse, msg: "the frame is not valid JSON"}
		}
		if m.JSONRPC != "2.0" {
			return message{}, &frameError{
				code: codeInvalidRequest,
				id:   m.ID,
				msg:  fmt.Sprintf("jsonrpc must be %q, got %q", jsonRPCVersion, m.JSONRPC),
			}
		}
		return m, nil
	}
}

// line reads one newline-terminated frame, refusing one over transportMax. A
// last line without a newline is returned, so a client that closes its output
// after one request is still answered.
func (d *decoder) line() ([]byte, error) {
	var buf []byte
	for {
		chunk, more, err := d.br.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return nil, errEOF
				}
				return trimCR(buf), nil
			}
			return nil, err
		}
		buf = append(buf, chunk...)
		if len(buf) > transportMax {
			return nil, &frameError{
				code: codeInvalidRequest,
				msg:  fmt.Sprintf("a frame is over the %d byte limit", transportMax),
			}
		}
		if !more {
			return trimCR(buf), nil
		}
	}
}

func trimCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpaceByte(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}
