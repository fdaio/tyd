package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConnectStatusNoTTYSilent(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, tty: false}
	s.Step(1, 4, "connecting")
	s.Clear()
	if buf.Len() != 0 {
		t.Fatalf("non-tty wrote %q", buf.String())
	}
}

func TestConnectStatusBarThenClear(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, tty: true}
	s.Step(2, 4, "connecting 10.0.0.1:1")
	got := buf.String()
	if !strings.Contains(got, "[==--]") || !strings.Contains(got, "connecting 10.0.0.1:1") {
		t.Fatalf("bar: %q", got)
	}
	s.Clear()
	if !strings.HasSuffix(buf.String(), "\r\033[K") {
		t.Fatalf("clear: %q", buf.String())
	}
}

func TestConnectStatusLeaveEndsWithNewline(t *testing.T) {
	var buf bytes.Buffer
	s := &connectStatus{w: &buf, tty: true}
	s.Leave("detaching")
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("want trailing newline, got %q", buf.String())
	}
	if strings.HasSuffix(buf.String(), "detaching\n") {
		t.Fatal("leave status should be cleared before newline")
	}
}
