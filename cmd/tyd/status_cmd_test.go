package main

import (
	"fmt"
	"strings"
	"testing"

	"tyd/internal/client"
	"tyd/internal/transport"
)

func TestFormatStatusConnErr(t *testing.T) {
	ep := client.Endpoint{Kind: transport.KindUnix, Address: "/tmp/tyd.sock"}
	got := formatStatusConnErr(ep, fmt.Errorf("dial unix /tmp/tyd.sock: connect: connection refused"))
	if got != "local daemon not running; start with tyd up" {
		t.Fatalf("got %q", got)
	}
	got = formatStatusConnErr(ep, fmt.Errorf("connect: invalid argument"))
	if got != "local daemon not running; start with tyd up" {
		t.Fatalf("invalid argument: %q", got)
	}
	if strings.Contains(got, "peer") || strings.Contains(got, "/tmp/tyd.sock") {
		t.Fatalf("leaked internals: %q", got)
	}
	tls := client.Endpoint{Kind: transport.KindTLS, Address: "10.0.0.1:1"}
	got = formatStatusConnErr(tls, fmt.Errorf("connection refused (is 'tyd up' running on the peer?)"))
	if !strings.HasPrefix(got, "daemon unreachable:") {
		t.Fatalf("tls: %q", got)
	}
}
