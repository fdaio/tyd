package main

import (
	"slices"
	"testing"

	"tyd/internal/paths"
)

func TestRelayURLs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty uses default", raw: "", want: []string{paths.DefaultRelay()}},
		{name: "single", raw: "https://relay-1.getfda.dev", want: []string{"https://relay-1.getfda.dev"}},
		{
			name: "list keeps order",
			raw:  "https://relay-1.getfda.dev,https://relay-2.getfda.dev",
			want: []string{"https://relay-1.getfda.dev", "https://relay-2.getfda.dev"},
		},
		{
			name: "list tolerates spaces and empties",
			raw:  " https://a , , https://b ,",
			want: []string{"https://a", "https://b"},
		},
		{name: "dedupes", raw: "https://a,https://b,https://a", want: []string{"https://a", "https://b"}},
		{name: "off disables", raw: "off", want: nil},
		{name: "off among entries disables only that entry", raw: "off,https://a", want: []string{"https://a"}},
		{name: "separators only yield no relays", raw: ",", want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := relayURLs(options{relay: tc.raw})
			if !slices.Equal(got, tc.want) {
				t.Fatalf("relayURLs(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestRelayURLDisplay(t *testing.T) {
	if got := relayURL(options{relay: "https://a,https://b"}); got != "https://a,https://b" {
		t.Fatalf("display = %q", got)
	}
	if got := relayURL(options{relay: "off"}); got != "off" {
		t.Fatalf("off display = %q", got)
	}
	if got := relayURL(options{relay: ""}); got != paths.DefaultRelay() {
		t.Fatalf("default display = %q", got)
	}
}
