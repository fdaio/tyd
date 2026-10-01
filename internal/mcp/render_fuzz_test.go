package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A page of hostile bytes must not be able to break the three things a caller
// relies on: the cap holds, the result decodes, and the offsets the model is told
// to page back with actually address the bytes that were left out.
func FuzzRenderKeepsItsInvariants(f *testing.F) {
	f.Add([]byte("hello"), uint64(0), uint64(1), false, false, false)
	f.Add([]byte("out\x00\xff\xfe and \x1b[31m colour\x1b[0m"), uint64(10), uint64(2), true, true, false)
	f.Add([]byte(strings.Repeat("y", 40000)), uint64(1<<20), uint64(3), true, false, true)
	f.Add([]byte("`"+"`"+"`"), uint64(0), uint64(0), false, true, true)
	f.Add([]byte("password: "), uint64(7), uint64(1), false, true, false)
	f.Add([]byte(""), uint64(0), uint64(0), false, false, true)

	f.Fuzz(func(t *testing.T, data []byte, dropped uint64, epoch uint64,
		cursorAhead, exited, wantHuman bool) {
		page := Page{
			Data:        data,
			CursorNext:  dropped + uint64(len(data)),
			Dropped:     dropped,
			Epoch:       epoch,
			CursorAhead: cursorAhead,
			Exited:      exited,
			Reason:      "fuzz",
		}
		attach := ""
		if wantHuman {
			attach = "tyd session attach build"
		}
		text, res := render(Session{ID: "s1", Alias: "build", Peer: "laptop"}, page, dropped, attach)
		if res == nil {
			t.Fatal("render returned no result")
		}

		// The model reads text, and a client has to be able to decode it.
		if !utf8.ValidString(text) {
			t.Fatalf("result text is not valid UTF-8 (len %d)", len(text))
		}
		if !utf8.ValidString(res.Output) {
			t.Fatalf("output is not valid UTF-8 (len %d)", len(res.Output))
		}

		// The cap. The body is fenced and may carry an omission marker, so the
		// bound is on the bytes the result claims to hold, which is the raw page
		// the head and tail were cut from.
		if !res.Truncated && len(data) > outputCap {
			t.Fatalf("a page of %d bytes was not truncated", len(data))
		}
		if res.Truncated {
			if len(data) <= outputCap {
				t.Fatalf("a page of %d bytes was truncated", len(data))
			}
			// Head and tail together cannot exceed the cap, and the omitted range
			// is what is left.
			if res.OmittedTo <= res.OmittedFrom {
				t.Fatalf("omitted range is empty or reversed: %d..%d", res.OmittedFrom, res.OmittedTo)
			}
			omitted := res.OmittedTo - res.OmittedFrom
			if omitted+headKeep+tailKeep != uint64(len(data)) {
				t.Fatalf("omitted %d plus head %d plus tail %d is not the page's %d bytes",
					omitted, headKeep, tailKeep, len(data))
			}
			// The offsets are stream positions, so they have to start where the
			// page started or a model paging back would be sent somewhere else.
			if res.OmittedFrom < dropped {
				t.Fatalf("omitted_from %d is before the page's own start %d", res.OmittedFrom, dropped)
			}
			if res.OmittedTo > dropped+uint64(len(data)) {
				t.Fatalf("omitted_to %d is past the end of the page (%d)",
					res.OmittedTo, dropped+uint64(len(data)))
			}
		}

		// The target is named on every result, and a result with no attach command
		// does not point at one.
		if res.Peer != "laptop" || !strings.Contains(text, "target=laptop") {
			t.Fatalf("the result does not name its target: peer=%q text=%q", res.Peer, text)
		}
		if wantHuman && !strings.Contains(text, attach) {
			t.Fatal("a result with an attach command must offer it")
		}
		if !wantHuman && strings.Contains(text, "password prompt") {
			t.Fatal("a result with no attach command must not advise handing over")
		}
		if res.Cursor != page.CursorNext {
			t.Fatalf("cursor = %d, want the page's %d", res.Cursor, page.CursorNext)
		}
	})
}
