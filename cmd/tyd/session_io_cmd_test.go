package main

import (
	"flag"
	"testing"
)

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

// session read and session send parse their own flags, so parseArgs must hand
// them the tail instead of rejecting what it does not recognise. The session
// id may come before or after those flags, and global flags may come first.
func TestSubcommandFlagRouting(t *testing.T) {
	cases := []struct {
		args []string
		rest []string
	}{
		{[]string{"session", "send", "s1", "--json"}, []string{"send", "s1", "--json"}},
		{[]string{"session", "send", "--json", "s1"}, []string{"send", "--json", "s1"}},
		{[]string{"session", "read", "s1", "--cursor", "0", "--json"}, []string{"read", "s1", "--cursor", "0", "--json"}},
		{[]string{"--peer", "laptop", "session", "read", "s1", "--wait", "2s"}, []string{"read", "s1", "--wait", "2s"}},
		{[]string{"session", "send", "s1", `hello\n`}, []string{"send", "s1", `hello\n`}},
	}
	for _, tc := range cases {
		opts, err := parseArgs(tc.args)
		if err != nil {
			t.Errorf("%v: %v", tc.args, err)
			continue
		}
		if opts.cmd != "session" {
			t.Errorf("%v: cmd = %q, want session", tc.args, opts.cmd)
			continue
		}
		if len(opts.rest) != len(tc.rest) {
			t.Errorf("%v: rest = %v, want %v", tc.args, opts.rest, tc.rest)
			continue
		}
		for i := range tc.rest {
			if opts.rest[i] != tc.rest[i] {
				t.Errorf("%v: rest = %v, want %v", tc.args, opts.rest, tc.rest)
				break
			}
		}
	}
}

// Other subcommands keep the old behaviour: an unknown flag is still an error.
func TestUnknownFlagStillRejected(t *testing.T) {
	if _, err := parseArgs([]string{"session", "list", "--nope"}); err == nil {
		t.Fatal("want an error for an unknown flag on session list")
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
