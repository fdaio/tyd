package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// widestMetadata is a frame carrying the most metadata the feature allows: a write
// request, because it has a path and a root claim and a mode on top of everything a
// read reply has.
//
// The lengths are the ones fileroot enforces, not PATH_MAX, and the filler is `<`.
//
// **`<`, deliberately.** encoding/json escapes it to six bytes, so a test filled with a
// character that encodes as itself is not a worst case. That mistake shipped once: the
// slack was derived with `p` in the path, the write-direction test passed, and any path
// containing `<`, `>` or `&` still overflowed the frame by thousands of bytes.
func widestMetadata(n int) Frame {
	return Frame{
		Type: TypeFileWrite, ID: strings.Repeat("i", 64),
		SessionID: strings.Repeat("s", 64),
		Path:      strings.Repeat("<", 1024),
		Root:      strings.Repeat("<", 1024),
		Mode:      "replace", ExpectedSHA: strings.Repeat("e", 64),
		Data: make([]byte, n),
	}
}

// The widest reply, which is a read: a page plus the metadata a result carries.
func widestReply(n int) Frame {
	return Frame{
		Type: TypeFileResult, ID: strings.Repeat("i", 64),
		SessionID: strings.Repeat("s", 64),
		Path:      strings.Repeat("<", 1024), Root: strings.Repeat("<", 1024),
		SHA256: strings.Repeat("a", 64),
		Data:   make([]byte, n),
	}
}

func encodedLen(t *testing.T, f Frame) int {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

func fitsLimit(t *testing.T, mk func(int) Frame) int {
	t.Helper()
	limit := 0
	for lo, hi := 0, MaxFrame; lo <= hi; {
		mid := (lo + hi) / 2
		if encodedLen(t, mk(mid)) <= MaxFrame {
			limit = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return limit
}

// MaxDataBytes is a bound on the encoder's behaviour, so it is checked against the
// encoder in **both** directions, because they are not the same frame.
func TestMaxDataBytesFitsBothDirections(t *testing.T) {
	for name, mk := range map[string]func(int) Frame{
		"write request": widestMetadata,
		"read reply":    widestReply,
	} {
		if got := encodedLen(t, mk(MaxDataBytes)); got > MaxFrame {
			t.Errorf("%s at MaxDataBytes (%d) encodes to %d, over MaxFrame %d", name, MaxDataBytes, got, MaxFrame)
		}
		limit := fitsLimit(t, mk)
		if limit < MaxDataBytes {
			t.Errorf("%s cannot even carry MaxDataBytes: limit is %d", name, limit)
		}
		// Not wastefully loose. Too small shrinks the feature; too loose is the bug.
		if limit-MaxDataBytes > frameMetadataSlack {
			t.Errorf("%s: the real limit is %d but MaxDataBytes is %d, wasting %d bytes",
				name, limit, MaxDataBytes, limit-MaxDataBytes)
		}
		t.Logf("%-14s MaxDataBytes=%d limit=%d slack=%d overhead=%d",
			name, MaxDataBytes, limit, frameMetadataSlack, encodedLen(t, mk(0)))
	}
}
