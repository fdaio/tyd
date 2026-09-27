package main

import (
	"strings"
	"testing"
)

func TestAttachShortcutRewritesToSessionAttach(t *testing.T) {
	opts, err := parseArgs([]string{"--verbose", "xx.oo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttachShortcut(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "session" || opts.peer != "oo" || !opts.verbose {
		t.Fatalf("%+v", opts)
	}
	if strings.Join(opts.rest, " ") != "attach xx" {
		t.Fatalf("rest=%q", opts.rest)
	}
}

func TestAttachShortcutMatchingPeerFlag(t *testing.T) {
	opts, err := parseArgs([]string{"--peer", "oo", "xx.oo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttachShortcut(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.peer != "oo" || opts.cmd != "session" {
		t.Fatalf("%+v", opts)
	}
}

func TestAttachShortcutRejects(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "extra arg", args: []string{"xx.oo", "extra"}, want: "usage: tyd <session>.<peer>"},
		{name: "two dots", args: []string{"a.b.c"}, want: "exactly one dot"},
		{name: "empty session", args: []string{".oo"}, want: "exactly one dot"},
		{name: "empty peer", args: []string{"xx."}, want: "exactly one dot"},
		{name: "peer flag conflict", args: []string{"--peer", "other", "xx.oo"}, want: "does not match"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseArgs(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			err = applyAttachShortcut(&opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestAttachShortcutLeavesOrdinaryCommands(t *testing.T) {
	opts, err := parseArgs([]string{"session", "attach", "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if err := applyAttachShortcut(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.cmd != "session" || strings.Join(opts.rest, " ") != "attach abc" || opts.peer != "" {
		t.Fatalf("%+v", opts)
	}
}
