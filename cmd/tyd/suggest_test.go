package main

import "testing"

func TestSuggestCommand(t *testing.T) {
	sessionCmds := []string{"create", "list", "attach", "watch", "approve", "reject", "close", "help"}
	tests := []struct {
		in   string
		want string
	}{
		{"wacth", "watch"},
		{"wach", "watch"},
		{"attch", "attach"},
		{"atatch", "attach"},
		{"lsit", "list"},
		{"creat", "create"},
		{"clsoe", "close"},
		{"aproove", "approve"},
		{"help", ""}, // exact match is not a suggestion
		{"zzzz", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := suggestCommand(tt.in, sessionCmds)
		if got != tt.want {
			t.Fatalf("suggestCommand(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSuggestTopLevel(t *testing.T) {
	top := rootCommands()
	if got := suggestCommand("sesion", top); got != "session" {
		t.Fatalf("got %q", got)
	}
	if got := suggestCommand("statys", top); got != "status" {
		t.Fatalf("got %q", got)
	}
	if got := suggestCommand("per", top); got != "peer" {
		t.Fatalf("got %q", got)
	}
}
