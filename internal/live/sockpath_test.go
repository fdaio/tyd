package live

import (
	"strconv"
	"strings"
	"testing"
)

// A socket path that overruns AF_UNIX fails at connect time with "invalid
// argument" and nothing else, so the check has to catch it first and say
// enough for the user to act on it.
func TestCheckSockPathAcceptsShortPath(t *testing.T) {
	if err := CheckSockPath("/tmp/tyd-live/0123456789abcdef/sock"); err != nil {
		t.Fatalf("a short path should be accepted, got %v", err)
	}
}

func TestCheckSockPathRejectsLongPath(t *testing.T) {
	long := "/" + strings.Repeat("a", MaxSockPathLen) + "/sock"
	err := CheckSockPath(long)
	if err == nil {
		t.Fatal("a path past the limit should be rejected")
	}
	msg := err.Error()
	// The user has to shorten a directory, so the message must name the path,
	// the length, the limit and the lever to pull.
	for _, want := range []string{long, strconv.Itoa(len(long)), strconv.Itoa(MaxSockPathLen), "HOME"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message should mention %q, got %q", want, msg)
		}
	}
}

func TestCheckSockPathBoundary(t *testing.T) {
	exact := "/" + strings.Repeat("a", MaxSockPathLen-1)
	if len(exact) != MaxSockPathLen {
		t.Fatalf("test setup: want %d bytes, built %d", MaxSockPathLen, len(exact))
	}
	if err := CheckSockPath(exact); err != nil {
		t.Fatalf("a path of exactly the limit should be accepted, got %v", err)
	}
	if err := CheckSockPath(exact + "a"); err == nil {
		t.Fatal("one byte over the limit should be rejected")
	}
}

// A long HOME is the realistic cause, so the default live root must be
// checked the same way as any other.
func TestDefaultLiveRootFits(t *testing.T) {
	if got := SockPath(Dir("/tmp/tyd-live", "0123456789abcdef")); len(got) > MaxSockPathLen {
		t.Fatalf("the default root yields a %d byte path, over the limit: %s", len(got), got)
	}
}
