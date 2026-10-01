package strutil

import "testing"

// The rule exists because tyd renders these names into commands a person is asked
// to run. So the cases that matter are the ones that survive a shell's parser as a
// single word and still execute.

func TestShellSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"an ordinary name", "build", true},
		{"digits", "session2", true},
		{"the punctuation a name legitimately needs", "web-01_api.prod", true},
		{"a non-latin name", "构建", true},
		{"a non-latin name with a digit", "构建2", true},

		// Each of these is one word to the shell and still substitutes.
		{"backticks", "a`id`", false},
		{"dollar parens", "a$(id)", false},
		{"a bare dollar", "a$IFS", false},
		{"a semicolon", "a;id", false},
		{"a pipe", "a|id", false},
		{"single quotes", "a'id'", false},
		{"double quotes", `a"id"`, false},
		{"a redirect", "a>x", false},
		{"an ampersand", "a&&id", false},
		{"a newline", "a\nid", false},
		{"a space", "a id", false},
		{"a slash", "a/b", false},
		{"a glob", "*", false},
		{"a tilde", "~", false},
		{"an at sign", "a@b", false},
		{"a colon", "a:1", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShellSafe(tc.in); got != tc.want {
				t.Errorf("ShellSafe(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
