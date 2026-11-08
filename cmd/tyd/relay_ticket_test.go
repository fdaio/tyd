package main

import "testing"

func TestShortTicketHandlesUntrustedLengths(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"x", "x"},
		{"short", "short"},
		{"0123456789", "01234567"},
	} {
		if got := shortTicket(tc.in); got != tc.want {
			t.Errorf("shortTicket(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
