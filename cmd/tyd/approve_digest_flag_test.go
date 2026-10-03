package main

import (
	"strings"
	"testing"
)

// `--digest` was unreachable, and the tests did not notice.
//
// approveDigestArg takes an argument slice and picks --digest out of it. Its own tests
// call it directly, and they pass. What nobody checked is whether the flag survives
// parseArgs — and it did not, because the pass-through allowlist for subcommands that
// own their flags named read and send and not approve. So the daemon printed
// "tyd session approve <id> --digest <hex>" as its instruction to the operator, two
// documents repeated it, and the command failed with "unknown flag --digest".
//
// These go through parseArgs with real argv, because that is the boundary the flag
// disappeared at.

func TestDigestSurvivesArgParsing(t *testing.T) {
	for _, argv := range [][]string{
		{"session", "approve", "sess1", "--digest", "abc123"},
		{"session", "approve", "--digest", "abc123", "sess1"},
	} {
		opts, err := parseArgs(argv)
		if err != nil {
			t.Errorf("%v was rejected: %v", argv, err)
			continue
		}
		if got := approveDigestArg(opts.rest); got != "abc123" {
			t.Errorf("%v carried digest %q, want abc123 (rest=%q)", argv, got, opts.rest)
		}
	}
}

// The flag is optional, so an approval with none still parses and still decides the
// only pending request.
func TestApproveWithoutADigestStillParses(t *testing.T) {
	opts, err := parseArgs([]string{"session", "approve", "sess1"})
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if got := approveDigestArg(opts.rest); got != "" {
		t.Errorf("digest %q out of an approval that named none", got)
	}
	// And the session id is still reachable, which is the whole point of the command.
	// Read exactly the way the dispatcher reads it: opts.rest[1:], with the
	// subcommand stripped. The digest and the id come out of the same slice, so a
	// change that reordered them would break one while the other kept passing.
	args := opts.rest[1:]
	if got := firstArg(args); got != "sess1" {
		t.Errorf("session id lost: args=%q", args)
	}
}

// The subcommands that already worked must keep working, and the ones that own no
// flags must keep being strict — a pass-through that is too wide would silently accept
// typos on every session subcommand.
func TestThePassThroughIsNoWiderThanItShouldBe(t *testing.T) {
	for _, sub := range []string{"read", "send", "approve"} {
		if !sessionSubcommandsOwningFlags[sub] {
			t.Errorf("session %s owns flags but is not in the pass-through list", sub)
		}
		opts, err := parseArgs([]string{"session", sub, "sess1", "--some-own-flag", "v"})
		if err != nil {
			t.Errorf("session %s rejected its own flag: %v", sub, err)
			continue
		}
		if !strings.Contains(strings.Join(opts.rest, " "), "--some-own-flag") {
			t.Errorf("session %s lost its own flag: rest=%q", sub, opts.rest)
		}
	}
	// list, create and close own no flags, so an unknown one is still a typo.
	for _, sub := range []string{"list", "create", "close", "attach", "watch", "rm"} {
		if _, err := parseArgs([]string{"session", sub, "--not-a-flag"}); err == nil {
			t.Errorf("session %s accepted a flag it does not own", sub)
		}
	}
}

// Recorded rather than asserted as correct: a subcommand that owns its flags takes the
// whole tail, so a **global** flag written after it is ignored rather than rejected.
//
// This is pre-existing and it applies to session read and session send exactly as it
// does to approve — the early return is the same one. It is written down here because
// "silently ignored" is the worst of the three answers, and because a reader looking
// at this parser will otherwise assume the flag after the tail is read. Fixing it means
// deciding the precedence between global and subcommand flags for every subcommand,
// which is a larger change than adding one name to a list and does not belong in a fix
// for an unreachable --digest.
func TestAGlobalFlagAfterAnOwnedTailIsIgnored(t *testing.T) {
	opts, err := parseArgs([]string{"session", "approve", "sess1", "--digest", "abc", "--socket", "/tmp/x.sock"})
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if opts.socket == "/tmp/x.sock" {
		t.Skip("this parser now reads global flags after an owned tail; update this note")
	}
	// The same for the two that already worked, so the note cannot drift:
	for _, sub := range []string{"read", "send"} {
		o, err := parseArgs([]string{"session", sub, "sess1", "--socket", "/tmp/x.sock"})
		if err != nil {
			t.Fatalf("session %s: %v", sub, err)
		}
		if o.socket == "/tmp/x.sock" {
			t.Errorf("session %s reads a trailing global flag but approve does not; the three should agree", sub)
		}
	}
}

// `--digest` has to be discoverable. It was documented in two places and absent from
// the one place an operator looks for it, which is the same shape as the flag being
// unreachable: the reference described a control that help did not offer.
func TestDigestIsInTheApproveHelp(t *testing.T) {
	usage := sessionApproveUsage()
	if !strings.Contains(usage, "--digest") {
		t.Errorf("tyd session approve help does not mention --digest:\n%s", usage)
	}
}
