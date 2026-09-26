package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConnectStatusNoticeAlways(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, verbose: false}
	s.Notice("watching (read-only)")
	s.Log("should stay silent")
	if buf.String() != "watching (read-only)\r\n" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestConnectStatusVerboseSSHStyle(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, verbose: true}
	s.Log("Connecting to 10.0.0.1 port 22.")
	s.Log("Connection established.")
	got := buf.String()
	if !strings.Contains(got, "debug1: Connecting to 10.0.0.1 port 22.\r\n") {
		t.Fatalf("connect: %q", got)
	}
	if !strings.Contains(got, "debug1: Connection established.\r\n") {
		t.Fatalf("established: %q", got)
	}
	s.Leave("Detaching.")
	if !strings.HasSuffix(buf.String(), "debug1: Detaching.\r\n") {
		t.Fatalf("leave: %q", buf.String())
	}
}

func TestDialDebugMsg(t *testing.T) {
	got := dialDebugMsg("tls", "100.101.29.23:34759")
	if got != "Connecting to 100.101.29.23 port 34759." {
		t.Fatalf("%q", got)
	}
	got = dialDebugMsg("unix", "/tmp/tyd.sock")
	if got != "Connecting to unix /tmp/tyd.sock." {
		t.Fatalf("%q", got)
	}
}
