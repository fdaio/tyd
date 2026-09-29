package live

import "unicode/utf8"

// textCleaner turns raw terminal bytes into the text a person would see, so a
// match is not thrown off by colour codes or a progress bar redrawing a line.
//
// It handles the escapes a shell prompt actually produces: CSI sequences
// (colours, cursor moves), OSC strings (window titles, which end with BEL or
// ST), and the other string escapes. A partial sequence at the end of the
// input is held back rather than guessed at, because the rest may still be
// coming: a prompt split across two writes must not match on its first half.
//
// A lone CR redraws the current line, and a backspace erases the character
// before it, so the cleaner keeps the line under construction rather than
// emitting text that a later byte may overwrite. Text() returns everything
// settled so far plus that line, which is what a match should see.
type textCleaner struct {
	// pending holds a sequence that may continue in the next chunk.
	pending []byte
	// done is the text that can no longer be redrawn.
	done []byte
	// line is the line currently being drawn.
	line []byte
}

func newTextCleaner() *textCleaner { return &textCleaner{} }

// Feed consumes b. It returns the cleaned text available after this call.
func (c *textCleaner) Feed(b []byte) []byte {
	if len(c.pending) > 0 {
		b = append(append([]byte(nil), c.pending...), b...)
		c.pending = nil
	}
	var i int
	for i < len(b) {
		switch ch := b[i]; {
		case ch == 0x1b: // ESC
			n, ok := escapeLen(b[i:])
			if !ok {
				// Incomplete: hold it until the rest arrives.
				c.pending = append([]byte(nil), b[i:]...)
				return c.Text()
			}
			i += n
		case ch == '\r':
			// CRLF is one newline. A CR at the very end may be the first half
			// of a CRLF split across chunks, so hold it back too.
			if i+1 == len(b) {
				c.pending = []byte{ch}
				return c.Text()
			}
			if b[i+1] == '\n' {
				c.endLine()
				i += 2
				continue
			}
			c.line = c.line[:0]
			i++
		case ch == '\n':
			c.endLine()
			i++
		case ch == '\b':
			if len(c.line) > 0 {
				c.line = c.line[:len(c.line)-1]
			}
			i++
		case ch < 0x20 || ch == 0x7f:
			// Other control bytes carry no text.
			i++
		default:
			// Take a run of printable bytes up to the next control.
			j := i
			for j < len(b) && b[j] >= 0x20 && b[j] != 0x7f && b[j] != 0x1b {
				j++
			}
			c.line = append(c.line, b[i:j]...)
			i = j
		}
	}
	return c.Text()
}

func (c *textCleaner) endLine() {
	c.done = append(c.done, c.line...)
	c.done = append(c.done, '\n')
	c.line = c.line[:0]
}

// Text is everything cleaned so far: settled text plus the line being drawn.
func (c *textCleaner) Text() []byte {
	if len(c.line) == 0 {
		return c.done
	}
	out := make([]byte, 0, len(c.done)+len(c.line))
	out = append(out, c.done...)
	out = append(out, c.line...)
	return out
}

// escapeLen reports the length of the escape sequence at the start of b, and
// whether it is complete.
func escapeLen(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	switch b[1] {
	case '[': // CSI: parameters, then a final byte in @-~
		for i := 2; i < len(b); i++ {
			if b[i] >= 0x40 && b[i] <= 0x7e {
				return i + 1, true
			}
		}
		return 0, false
	case ']', 'P', 'X', '^', '_': // OSC, DCS, SOS, PM, APC: end with BEL or ST
		for i := 2; i < len(b); i++ {
			if b[i] == 0x07 {
				return i + 1, true
			}
			if b[i] == 0x1b {
				if i+1 == len(b) {
					return 0, false
				}
				if b[i+1] == '\\' {
					return i + 2, true
				}
			}
		}
		return 0, false
	default:
		// ESC plus one byte.
		return 2, true
	}
}

// CleanString is the one-shot form, for a buffer already known to be complete.
func CleanString(b []byte) string {
	return string(newTextCleaner().Feed(b))
}

// truncateUTF8 cuts n down to the nearest rune boundary, so a reply never
// splits a character. It backs off at most utf8.UTFMax-1 bytes.
func truncateUTF8(b []byte, n int) int {
	if n >= len(b) {
		return len(b)
	}
	if n <= 0 {
		return 0
	}
	// If n lands inside a rune, move back to that rune's first byte.
	for back := 0; back < utf8.UTFMax; back++ {
		p := n - back
		if p < 0 {
			return 0
		}
		if utf8.RuneStart(b[p]) {
			return p
		}
	}
	return n
}

// matchWindow bounds how much text a condition looks at. A busy session can
// outrun any regex, and a prompt is never 16KB back.
const matchWindow = 16 << 10

// lastWindow returns the tail of b starting at from, capped to matchWindow
// bytes measured from the end.
func lastWindow(b []byte, from int) []byte {
	if from < 0 {
		from = 0
	}
	if from > len(b) {
		from = len(b)
	}
	seg := b[from:]
	if len(seg) > matchWindow {
		// Start the window on a rune boundary.
		cut := truncateUTF8(seg, len(seg)-matchWindow)
		seg = seg[cut:]
	}
	return seg
}
