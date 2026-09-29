package main

import (
	"flag"
	"testing"
)

func TestParseSendData(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`echo hi\n`, "echo hi\n"},
		{`a\tb`, "a\tb"},
		{`a\rb`, "a\rb"},
		{`\x03`, "\x03"},
		{`\x1b[A`, "\x1b[A"},
		{`a\\b`, `a\b`},
		// No newline is ever added on its own.
		{`echo hi`, "echo hi"},
		{``, ""},
		{`mixed \n and \t and \\`, "mixed \n and \t and \\"},
	}
	for _, tc := range cases {
		got, err := parseSendData(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
	// Uppercase hex is what a person is most likely to type.
	if got, err := parseSendData(`\xFF`); err != nil || string(got) != "\xff" {
		t.Fatalf("\\xFF: %q %v", got, err)
	}
}

func TestParseSendDataErrors(t *testing.T) {
	for _, in := range []string{`trailing\`, `\xZZ`, `\x1`, `\q`} {
		if _, err := parseSendData(in); err == nil {
			t.Fatalf("%q: want an error", in)
		}
	}
}

func TestReadFlagsAfterSessionID(t *testing.T) {
	// The documented order puts the flags after the session id, which the
	// flag package alone would treat as positional.
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	cursor := fs.Uint64("cursor", 0, "")
	epoch := fs.Uint64("epoch", 0, "")
	wait := fs.Duration("wait", 0, "")
	asJSON := fs.Bool("json", false, "")
	follow := fs.Bool("follow", false, "")

	flagArgs, pos, err := splitFlags(fs, []string{"sess1", "--cursor", "42", "--epoch=7", "--wait", "3s", "--json", "--follow"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse(flagArgs); err != nil {
		t.Fatal(err)
	}
	if len(pos) != 1 || pos[0] != "sess1" {
		t.Fatalf("positional = %v", pos)
	}
	if *cursor != 42 || *epoch != 7 || wait.Seconds() != 3 || !*asJSON || !*follow {
		t.Fatalf("cursor=%d epoch=%d wait=%v json=%v follow=%v", *cursor, *epoch, *wait, *asJSON, *follow)
	}
}

func TestSplitFlagsRejectsUnknown(t *testing.T) {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	fs.Uint64("cursor", 0, "")
	if _, _, err := splitFlags(fs, []string{"sess1", "--nope", "1"}); err == nil {
		t.Fatal("want an error for an unknown flag")
	}
	if _, _, err := splitFlags(fs, []string{"sess1", "--cursor"}); err == nil {
		t.Fatal("want an error for a flag missing its value")
	}
}

// A boolean flag must not swallow the session id that follows it.
func TestSplitFlagsBoolDoesNotEatNext(t *testing.T) {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	fs.Bool("json", false, "")
	flagArgs, pos, err := splitFlags(fs, []string{"--json", "sess1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flagArgs) != 1 || flagArgs[0] != "--json" {
		t.Fatalf("flagArgs = %v", flagArgs)
	}
	if len(pos) != 1 || pos[0] != "sess1" {
		t.Fatalf("positional = %v", pos)
	}
}

// "--" ends flag parsing, so data that looks like a flag is data.
func TestSplitFlagsStopsAtDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	_, pos, err := splitFlags(fs, []string{"sess1", "--", "--not-a-flag"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 2 || pos[1] != "--not-a-flag" {
		t.Fatalf("positional = %v", pos)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
