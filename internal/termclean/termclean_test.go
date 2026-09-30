package termclean

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanRemovesColourCodes(t *testing.T) {
	// A coloured prompt is the case that matters.
	in := "\x1b[01;32muser@host\x1b[00m: \x1b[1;34m~/src\x1b[0m$ "
	if got := CleanString([]byte(in)); got != "user@host: ~/src$ " {
		t.Fatalf("got %q", got)
	}
}

func TestCleanRemovesOSC(t *testing.T) {
	cases := map[string]string{
		"title-bel":   "\x1b]0;some title\x07prompt$ ",
		"title-st":    "\x1b]0;some title\x1b\\prompt$ ",
		"title-split": "\x1b]0;some ti",
	}
	_ = cases
	if got := CleanString([]byte(cases["title-bel"])); got != "prompt$ " {
		t.Fatalf("BEL: got %q", got)
	}
	if got := CleanString([]byte(cases["title-st"])); got != "prompt$ " {
		t.Fatalf("ST: got %q", got)
	}
	// An unterminated OSC swallows what follows, exactly as a terminal does:
	// nothing is drawn until the string ends. The cleaner holds it back
	// because more bytes may still close it.
	if got := CleanString([]byte(cases["title-split"])); got != "" {
		t.Fatalf("unterminated OSC should draw nothing, got %q", got)
	}
}

func TestCleanCarriageReturnRedrawsLine(t *testing.T) {
	// A progress bar redraws the same line over and over.
	in := "downloading 10%\rdownloading 55%\rdownloading 100%\ndone"
	got := CleanString([]byte(in))
	if strings.Contains(got, "10%") || strings.Contains(got, "55%") {
		t.Fatalf("redrawn text survived: %q", got)
	}
	if !strings.Contains(got, "downloading 100%") || !strings.Contains(got, "done") {
		t.Fatalf("got %q", got)
	}
}

func TestCleanCRLFAndBackspace(t *testing.T) {
	if got := CleanString([]byte("line\r\nnext")); got != "line\nnext" {
		t.Fatalf("CRLF: got %q", got)
	}
	// A backspace erases the character before it.
	if got := CleanString([]byte("tyd\b\n")); got != "ty\n" {
		t.Fatalf("backspace: got %q", got)
	}
	// Backspace on an empty line must not panic.
	if got := CleanString([]byte("\b\bok")); got != "ok" {
		t.Fatalf("leading backspace: got %q", got)
	}
}

// A prompt split across two writes must not match on the first half. The
// cleaner holds an incomplete sequence back until the rest arrives.
func TestCleanHoldsPartialEscape(t *testing.T) {
	c := New()
	first := c.Feed([]byte("user@host\x1b[01;3"))
	if strings.Contains(string(first), "01;3") {
		t.Fatalf("partial CSI leaked: %q", first)
	}
	if !strings.Contains(string(first), "user@host") {
		t.Fatalf("printable part lost: %q", first)
	}
	// The rest of the sequence arrives, followed by the prompt.
	second := c.Feed([]byte("2m$ "))
	if strings.Contains(string(second), "01;3") || strings.Contains(string(second), "2m") {
		t.Fatalf("sequence leaked: %q", second)
	}
	if !strings.Contains(string(second), "$ ") {
		t.Fatalf("prompt lost: %q", second)
	}
}

// A prompt split in the middle of plain text must still be matchable, because
// the caller sees the tail once the second half lands.
func TestCleanAcrossChunksPrompt(t *testing.T) {
	c := New()
	first := c.Feed([]byte("pass"))
	if !strings.Contains(string(first), "pass") {
		t.Fatalf("first chunk: %q", first)
	}
	// Text() is cumulative, so the second chunk shows the whole line.
	second := c.Feed([]byte("word: "))
	if !strings.Contains(string(second), "password: ") {
		t.Fatalf("got %q", second)
	}
}

// A CR at the end of a chunk must be held back, because the next chunk may
// start with LF and make it a CRLF.
func TestCleanHoldsTrailingCR(t *testing.T) {
	c := New()
	first := c.Feed([]byte("done\r"))
	if strings.Contains(string(first), "\n") {
		t.Fatalf("CR turned into a newline early: %q", first)
	}
	second := c.Feed([]byte("\nnext"))
	if got := string(second); got != "done\nnext" {
		t.Fatalf("got %q", got)
	}
}

func TestTruncateUTF8(t *testing.T) {
	// Four 3-byte runes.
	s := []byte("你好世界")
	cases := map[int]int{0: 0, 1: 0, 2: 0, 3: 3, 4: 3, 5: 3, 6: 6, 9: 9, 12: 12}
	for n, want := range cases {
		if got := TruncateUTF8(s, n); got != want {
			t.Fatalf("truncate(%d) = %d, want %d", n, got, want)
		}
	}
	// Past the end is clamped, not an error.
	if got := TruncateUTF8(s, 99); got != len(s) {
		t.Fatalf("clamp: %d", got)
	}
	// ASCII is never moved.
	if got := TruncateUTF8([]byte("abcdef"), 3); got != 3 {
		t.Fatalf("ascii: %d", got)
	}
}

func TestLastWindow(t *testing.T) {
	b := []byte(strings.Repeat("a", MatchWindow*2))
	w := LastWindow(b, 0)
	if len(w) != MatchWindow {
		t.Fatalf("window = %d", len(w))
	}
	// A cursor inside the data starts from the cursor.
	w = LastWindow(b, MatchWindow)
	if len(w) != MatchWindow {
		t.Fatalf("window from cursor = %d", len(w))
	}
	// A cursor past the end is empty, not a panic.
	if w := LastWindow(b, len(b)+10); len(w) != 0 {
		t.Fatalf("past end = %d", len(w))
	}
	// A cursor before the start is clamped.
	if w := LastWindow(b, -5); len(w) != MatchWindow {
		t.Fatalf("negative cursor = %d", len(w))
	}
}

// Cleaning must never turn valid text into invalid text. An escape sequence that
// swallowed the first byte of a multi-byte rune, or a backspace that dropped one
// byte of it, would leave the rest of the rune behind as a broken sequence — and
// every caller hands the result to something that has to decode it.
//
// Bytes that were already invalid are not this package's business: it removes
// escapes, and a caller that needs valid UTF-8 replaces undecodable bytes before
// it gets here. The invariant is one-directional on purpose.
func TestCleaningNeverBreaksAValidRune(t *testing.T) {
	for _, in := range []string{
		"\x1b\ufffd",     // an escape, then a replacement character
		"\x1b\x1b\ufffd", // an escape, another escape, a replacement character
		"before\x1bé",    // a rune split by an escape
		"\x1bé",          // a real character straight after an escape
		"\x1b]0;t\ufffd", // an OSC that never ends, then a replacement character
		"é\x08",          // a backspace over a multi-byte character
		"aé\x08\x08z",    // two backspaces, the second one past the start
		"\ufffd\ufffd",   // two replacement characters
		"éèê",            // multi-byte characters on their own
	} {
		if !utf8.ValidString(in) {
			t.Fatalf("test input %q is not valid to begin with", in)
		}
		out := CleanString([]byte(in))
		if !utf8.ValidString(out) {
			t.Errorf("CleanString(%q) = %q, which is not valid UTF-8", in, out)
		}
	}
	// The text is kept: dropping the escape must not swallow the character after
	// it, or output in a non-ASCII locale would go missing.
	if got := CleanString([]byte("\x1bé")); got != "é" {
		t.Errorf("CleanString = %q, want %q", got, "é")
	}
	// And a backspace takes the whole character with it, the way a terminal's
	// cursor moves back over a column.
	if got := CleanString([]byte("é\x08")); got != "" {
		t.Errorf("CleanString = %q, want the character erased", got)
	}
	if got := CleanString([]byte("aé\x08")); got != "a" {
		t.Errorf("CleanString = %q, want %q", got, "a")
	}
}
