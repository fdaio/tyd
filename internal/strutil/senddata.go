package strutil

import (
	"fmt"
	"strconv"
)

// ParseSendData expands the escapes a person or a model types: \n, \r, \t, \xHH
// and \\. It never appends a newline: what is sent is what was asked for.
//
// A send is a keystroke stream, not text, so an unescaped control byte in the
// argument would be typed rather than shown. The escapes keep the argument
// writable as one word.
func ParseSendData(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("trailing backslash")
		}
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("\\x needs two hex digits")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bad \\x escape: %w", err)
			}
			out = append(out, byte(v))
			i += 2
		default:
			return nil, fmt.Errorf("unknown escape \\%s", string(s[i]))
		}
	}
	return out, nil
}
