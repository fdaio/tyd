package strutil

import (
	"bytes"
	"testing"
)

func TestParseSendData(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", nil},
		{"ls -la", []byte("ls -la")},
		// No newline is added on its own: what is typed is what was asked for.
		{"ls -la\n", []byte("ls -la\n")},
		{"ls -la", []byte("ls -la")},
		{"a\r\n\tb", []byte("a\r\n\tb")},
		{`a\r\n\tb`, []byte("a\r\n\tb")},
		{`\\`, []byte(`\`)},
		{`a\\b`, []byte(`a\b`)},
		{`\x03`, []byte{0x03}},
		{`\x00`, []byte{0x00}},
		{`\xff`, []byte{0xff}},
		{`echo \x41`, []byte("echo A")},
		// Uppercase hex is what a person is most likely to type.
		{`\xFF`, []byte{0xff}},
		// An arrow key is one control byte followed by two printable ones.
		{`\x1b[A`, []byte("\x1b[A")},
		// A backslash that is not an escape is an error rather than a literal,
		// because silently typing one would send something nobody asked for.
		{`a\qb`, nil},
		{`trailing\`, nil},
		{`\x1`, nil},
		{`\xzz`, nil},
	}
	for _, c := range cases {
		got, err := ParseSendData(c.in)
		if c.want == nil && c.in != "" {
			if err == nil {
				t.Errorf("ParseSendData(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSendData(%q): %v", c.in, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("ParseSendData(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseSendDataLeavesPlainTextAlone(t *testing.T) {
	// A Windows path and a JSON fragment are both things a person types, so a
	// backslash they did not mean as an escape has to be written as \\.
	got, err := ParseSendData(`C:\Users\me`)
	if err == nil {
		t.Fatalf("ParseSendData kept an unknown escape: %q", got)
	}
	got, err = ParseSendData(`C:\\Users\\me`)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `C:\Users\me` {
		t.Fatalf("got %q", got)
	}
}
