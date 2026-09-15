package main

import (
	"os"
	"testing"
)

func TestEnvOr(t *testing.T) {
	t.Setenv("TYD_CP_TEST_EMPTY", "")
	if got := envOr("TYD_CP_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Fatalf("empty env: %q", got)
	}
	t.Setenv("TYD_CP_TEST_SET", "  value  ")
	if got := envOr("TYD_CP_TEST_SET", "fallback"); got != "value" {
		t.Fatalf("set env: %q", got)
	}
	_ = os.Unsetenv("TYD_CP_TEST_MISSING")
	if got := envOr("TYD_CP_TEST_MISSING", "fb"); got != "fb" {
		t.Fatalf("missing: %q", got)
	}
}
