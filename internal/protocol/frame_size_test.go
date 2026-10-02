package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// MaxDataBytes is derived from the encoder's behaviour, so it is checked against it
// rather than trusted.
func TestMaxDataBytesFitsAndIsNotWastefullyLoose(t *testing.T) {
	// The metadata at its widest a real reply carries, so the check is not flattering.
	full := func(n int) Frame {
		return Frame{
			Type: TypeFileResult, ID: strings.Repeat("i", 64),
			SessionID: strings.Repeat("s", 64), Path: strings.Repeat("p", 1024),
			SHA256: strings.Repeat("a", 64), Root: strings.Repeat("r", 1024),
			Data: make([]byte, n),
		}
	}
	encoded := func(f Frame) int {
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}

	// The guarantee: a payload of this size, with the widest metadata, still fits.
	if got := encoded(full(MaxDataBytes)); got > MaxFrame {
		t.Errorf("a frame with MaxDataBytes (%d) encodes to %d, over MaxFrame %d", MaxDataBytes, got, MaxFrame)
	}

	// And it is not wastefully conservative: the real boundary is within the reserved
	// slack of it. Being loose would quietly shrink the feature; being tight by a
	// couple of kilobytes costs nothing, and the slack is what buys correctness.
	limit := 0
	for lo, hi := MaxDataBytes, MaxFrame; lo <= hi; {
		mid := (lo + hi) / 2
		if encoded(full(mid)) <= MaxFrame {
			limit = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if limit-MaxDataBytes > frameMetadataSlack {
		t.Errorf("the real limit is %d but MaxDataBytes is %d, wasting %d bytes of payload",
			limit, MaxDataBytes, limit-MaxDataBytes)
	}
	t.Logf("MaxDataBytes=%d, encoder boundary=%d, slack=%d", MaxDataBytes, limit, frameMetadataSlack)
}
