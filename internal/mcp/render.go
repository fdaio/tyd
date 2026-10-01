package mcp

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"tyd/internal/ttyutil"
	"unicode/utf8"

	"tyd/internal/termclean"
)

const (
	// outputCap is the ceiling on one result. A page can be 64KB, which is far
	// more than a model should read in one go.
	outputCap = 8 << 10
	// headKeep and tailKeep split outputCap. The head carries the command that
	// was run, the tail carries the answer, and the answer is the part a model
	// acts on.
	headKeep = 2 << 10
	tailKeep = outputCap - headKeep
)

// passwordPrompt matches a last line that asks for a secret. A model that types
// a password into a remote session has leaked it into that session's log, so
// the footer says to hand the session to a person instead.
//
// The echo state of the PTY would answer this reliably, but the daemon does not
// report it yet. A regex costs a false positive on a prompt that never receives
// input, and the footer only advises.
var passwordPrompt = regexp.MustCompile(`(?i)(password|passphrase|密码|口令)[^\n]{0,40}[:：]\s*$`)

// result is the structured content of a tool call. Everything a model needs to
// decide what to do next is a field, so it does not have to parse the text.
type result struct {
	Output string `json:"output"`
	// Reason is why the read returned: available, idle, match, max_bytes,
	// timeout, exited or cursor_ahead.
	Reason string `json:"reason"`
	// SessionState is running or exited.
	SessionState string `json:"session_state"`
	// Cursor is where the next session_read starts.
	Cursor uint64 `json:"cursor"`
	// Gap is the number of bytes the target could not show.
	Gap uint64 `json:"gap"`
	// Truncated says outputCap cut this result.
	Truncated bool `json:"truncated"`
	// OmittedFrom and OmittedTo bound the raw bytes the cap removed. They are
	// stream positions, so a model pages them back with
	// session_read {cursor: omitted_from}.
	OmittedFrom uint64 `json:"omitted_from,omitempty"`
	OmittedTo   uint64 `json:"omitted_to,omitempty"`
	// Written is the byte count of a send.
	Written *int `json:"written,omitempty"`
	// Session is the alias, or the id when the session has no alias.
	Session string `json:"session,omitempty"`
	// Peer is the machine the call ran on. It is a field as well as a line in
	// the footer because a model that cannot read the text still has to know
	// which of the offered machines it just typed into.
	Peer string `json:"peer,omitempty"`
	// HumanAttach is the command that hands the session to a person.
	HumanAttach string `json:"human_attach,omitempty"`
	// Sessions is the row list of session_list.
	Sessions []sessionRow `json:"sessions,omitempty"`
	// Tty is the target terminal's line discipline as of this result. The bits are
	// reported raw as well as derived, because a derived field that turns out to be
	// wrong is a change of derivation rather than a change of contract.
	Tty *ttyState `json:"tty,omitempty"`
}

// ttyState is what the terminal was doing when the page was taken. InputMode is
// derived from the bits; see internal/ttyutil for why those two bits and not one.
type ttyState struct {
	Echo      bool   `json:"echo"`
	Icanon    bool   `json:"icanon"`
	InputMode string `json:"input_mode"`
	// Why is set only when the target did not report the state, so a model is told
	// it is unknown rather than left to read a zero value as "not echoing".
	Why string `json:"why,omitempty"`
}

// sessionRow is one row of session_list.
type sessionRow struct {
	Session string `json:"session"`
	ID      string `json:"id"`
	Peer    string `json:"peer"`
	// Recorded is what the local catalog holds, which a probe can contradict.
	Recorded string `json:"recorded_state,omitempty"`
	// State is what the probe read found: running, exited or unknown.
	State string `json:"state"`
	// Probed says whether the state came from the target. It is false when the
	// target was not asked, which is different from being asked and failing: a
	// row that was never probed has no state to doubt.
	Probed bool `json:"probed"`
	// ProbeError is why the probe did not answer, or why it was not made.
	ProbeError string `json:"probe_error,omitempty"`
	// OpenedByUs marks a session this process created, which --close-on-exit
	// will end.
	OpenedByUs bool   `json:"opened_by_this_process"`
	Created    string `json:"created,omitempty"`
}

// render turns a page into the text a model reads, plus the structured content
// behind it.
//
// The cap is applied to the raw bytes, not to the cleaned text, because a cursor
// addresses the raw stream: cleaning first would replace every invalid byte with
// a three-byte marker and move every position after it. So the head and the tail
// are cut from the raw page and cleaned separately afterwards. Cleaning them
// apart is also what a cleaner needs: it holds back an unterminated escape
// sequence, so feeding it a cut stream would hold back the whole tail.
func render(s Session, p Page, start uint64, humanAttach string) (string, *result) {
	raw := p.Data

	var gapNote string
	gap := p.Dropped
	switch {
	case p.CursorAhead:
		// The target resumed at its own earliest cursor, so the distance back to
		// what the caller asked for is unknown. Report the position instead of
		// inventing a byte count.
		gapNote = fmt.Sprintf("[output gap: output before cursor %d is no longer available]\n", start)
		if gap == 0 {
			gap = 1
		}
	case p.Dropped > 0:
		gapNote = fmt.Sprintf("[output gap: %d bytes not shown]\n", p.Dropped)
	}

	var (
		head, tail  []byte
		omittedFrom uint64
		omittedTo   uint64
		truncated   bool
	)
	if len(raw) > outputCap {
		h := termclean.TruncateUTF8(raw, headKeep)
		t := advanceRune(raw, len(raw)-tailKeep)
		head, tail = raw[:h], raw[t:]
		omittedFrom = start + uint64(h)
		omittedTo = start + uint64(t)
		truncated = true
	} else {
		head = raw
	}

	body := termclean.CleanString(utf8Clean(head))
	if truncated {
		omitted := omittedTo - omittedFrom
		body += fmt.Sprintf("\n[... %d bytes omitted ...]\n%s", omitted, termclean.CleanString(utf8Clean(tail)))
	}

	state := "running"
	if p.Exited {
		state = "exited"
	}

	// The target leads the footer. A result that said only why it returned
	// would leave a model that serves several machines unable to tell which one
	// answered, and the operator reading along unable to tell where a command
	// ran at all.
	footer := fmt.Sprintf("[tyd: target=%s reason=%s state=%s]", orLocal(s.Peer), orUnknown(p.Reason), state)
	if truncated {
		footer += fmt.Sprintf("\n[%d bytes omitted: page them back with "+
			"session_read {cursor: %d, max_bytes: %d}]", omittedTo-omittedFrom, omittedFrom, outputCap)
	}
	if humanAttach != "" {
		// The takeover command goes in the text, not only in the structured
		// content: a client that shows only the text would otherwise leave the
		// model unable to hand the session to the user.
		footer += fmt.Sprintf("\n[a human can take this session over with: %s]", humanAttach)
	}
	if t := ttyOf(p); t.Why == "" && t.InputMode == string(ttyutil.InputSecretLikely) {
		// The regex above is a guess over the text; this is the terminal's own
		// answer. Both are reported, and where they disagree the terminal is right.
		footer += fmt.Sprintf("\n[the terminal is not echoing: this looks like a prompt asking for a secret. " +
			"Pass secret:true on session_send and the target will refuse rather than echo the bytes.]")
	}
	if humanAttach != "" && looksLikePasswordPrompt(body) {
		footer += fmt.Sprintf("\n[the last line looks like a password prompt: do not type into it. "+
			"Ask the user to run `%s` and take the session over]", humanAttach)
	}

	text := fence(body) + "\n" + footer
	if gapNote != "" {
		text = gapNote + text
	}

	return text, &result{
		Output:       body,
		Reason:       orUnknown(p.Reason),
		SessionState: state,
		Cursor:       p.CursorNext,
		Gap:          gap,
		Truncated:    truncated,
		OmittedFrom:  omittedFrom,
		OmittedTo:    omittedTo,
		Session:      s.Label(),
		Peer:         orLocal(s.Peer),
		HumanAttach:  humanAttach,
		Tty:          ttyOf(p),
	}
}

// ttyOf reports the terminal state the page carries, or says it is unknown.
//
// Unknown is spelled out rather than left as two false bits, because two false
// bits read as "the terminal is not echoing", which is the one thing a caller must
// not conclude from a target that did not answer.
func ttyOf(p Page) *ttyState {
	if p.Echo == nil || p.Icanon == nil {
		return &ttyState{Why: "the target did not report its terminal state, so it is unknown"}
	}
	st := ttyutil.EchoState{Echo: *p.Echo, Icanon: *p.Icanon}
	return &ttyState{
		Echo:      *p.Echo,
		Icanon:    *p.Icanon,
		InputMode: st.InputMode().String(),
	}
}

// looksLikePasswordPrompt reports whether the last non-empty line of body asks
// for a secret.
func looksLikePasswordPrompt(body string) bool {
	lines := strings.Split(body, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		return passwordPrompt.MatchString(lines[i])
	}
	return false
}

// fence wraps body in a backtick run one longer than the longest run inside it.
// A page is untrusted data: without the fence, output that looks like a closing
// fence followed by an instruction is read as an instruction.
func fence(body string) string {
	longest, run := 0, 0
	for _, r := range body {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	marks := strings.Repeat("`", n)
	return marks + "text\n" + body + "\n" + marks
}

// advanceRune moves n forward to the next rune boundary, so a cut never splits
// a character.
func advanceRune(b []byte, n int) int {
	switch {
	case n <= 0:
		return 0
	case n >= len(b):
		return len(b)
	}
	for n < len(b) && !utf8.RuneStart(b[n]) {
		n++
	}
	return n
}

// orUnknown keeps an empty reason visible instead of rendering a blank field.
func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// firstContactLimit is how much output a process shows the first time it looks
// at a session it has not read before. A session can hold a whole build log, and
// the caller asked to open a shell, not to read the last day of output.
const firstContactLimit = 4 << 10

// trimFirstContact keeps the tail of a page for a first contact. The tail holds
// the prompt and the last command, which is what tells a model the state of the
// shell.
func trimFirstContact(p Page) Page {
	if len(p.Data) <= firstContactLimit {
		return p
	}
	cut := advanceRune(p.Data, len(p.Data)-firstContactLimit)
	out := p
	out.Data = append([]byte(nil), p.Data[cut:]...)
	// The dropped prefix is real, so report it rather than pretending the page
	// began where the caller asked.
	out.Dropped = p.Dropped + uint64(cut)
	return out
}

// utf8Clean replaces invalid sequences, so a page from a binary or a
// half-written rune cannot make the result undecodable.
func utf8Clean(b []byte) []byte {
	if utf8.Valid(b) {
		return b
	}
	return bytes.ToValidUTF8(b, []byte("\uFFFD"))
}
