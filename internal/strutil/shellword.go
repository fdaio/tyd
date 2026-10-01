package strutil

import "unicode"

// ShellSafe reports whether s can be pasted into a shell as a single word with
// nothing executed.
//
// tyd renders names into commands it then asks a person to run — "ask the user to
// run `tyd session attach build`" — so a name carrying a metacharacter is not a
// cosmetic problem. Refusing whitespace and a slash was not enough: a backtick
// and $( ) are one word to the shell's parser and still substitute, and both fit
// inside a name that has no slash and no space.
//
// Letters and digits pass whatever their script. A name written in a non-Latin
// alphabet is still one inert word, and refusing it would cost real users more
// than the substitution this guards against.
func ShellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '-', '_', '.':
		default:
			return false
		}
	}
	return true
}
