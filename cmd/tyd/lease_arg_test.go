package main

import (
	"testing"
	"time"
)

func TestApproveLeaseArg(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want time.Duration
		bad  bool
	}{
		{[]string{"sess", "--lease", "15m"}, 15 * time.Minute, false},
		{[]string{"--lease=1h", "sess"}, time.Hour, false},
		{[]string{"sess"}, 0, false},
		{[]string{"sess", "--lease", "0s"}, 0, true},
		{[]string{"sess", "--lease", "2h"}, 0, true},
		{[]string{"sess", "--lease"}, 0, true},
	} {
		got, err := approveLeaseArg(tc.args)
		if tc.bad {
			if err == nil {
				t.Errorf("%v: expected an error", tc.args)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%v: got %s, %v; want %s", tc.args, got, err, tc.want)
		}
	}
}
