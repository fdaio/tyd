package live

import (
	"strings"
	"testing"
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
	c := newTextCleaner()
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
	c := newTextCleaner()
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
	c := newTextCleaner()
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
		if got := truncateUTF8(s, n); got != want {
			t.Fatalf("truncate(%d) = %d, want %d", n, got, want)
		}
	}
	// Past the end is clamped, not an error.
	if got := truncateUTF8(s, 99); got != len(s) {
		t.Fatalf("clamp: %d", got)
	}
	// ASCII is never moved.
	if got := truncateUTF8([]byte("abcdef"), 3); got != 3 {
		t.Fatalf("ascii: %d", got)
	}
}

func TestLastWindow(t *testing.T) {
	b := []byte(strings.Repeat("a", matchWindow*2))
	w := lastWindow(b, 0)
	if len(w) != matchWindow {
		t.Fatalf("window = %d", len(w))
	}
	// A cursor inside the data starts from the cursor.
	w = lastWindow(b, matchWindow)
	if len(w) != matchWindow {
		t.Fatalf("window from cursor = %d", len(w))
	}
	// A cursor past the end is empty, not a panic.
	if w := lastWindow(b, len(b)+10); len(w) != 0 {
		t.Fatalf("past end = %d", len(w))
	}
	// A cursor before the start is clamped.
	if w := lastWindow(b, -5); len(w) != matchWindow {
		t.Fatalf("negative cursor = %d", len(w))
	}
}
