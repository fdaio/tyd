package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWritePeerShowFieldsLabels(t *testing.T) {
	var buf bytes.Buffer
	writePeerShowFields(&buf, "abc", "amy", "outbound", "2026-09-16T09:53:22Z", "2pwNT1Vzrv7jw+1w…")
	out := buf.String()
	for _, bad := range []string{"paired_at", "public_key"} {
		if strings.Contains(out, bad) {
			t.Fatalf("snake_case label %q in CLI output: %q", bad, out)
		}
	}
	for _, want := range []string{"id:", "alias:", "direction:", "paired:", "public key:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}
