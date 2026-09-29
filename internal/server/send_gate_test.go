package server

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/protocol"
	"tyd/internal/transport"
)

func frameSend(id, data string) protocol.Frame {
	return protocol.Frame{Type: protocol.TypeSend, SessionID: id, Data: []byte(data)}
}

func frameRead(id string) protocol.Frame {
	return protocol.Frame{Type: protocol.TypeRead, SessionID: id}
}

func sendOnce(t *testing.T, ep client.Endpoint, key ed25519.PrivateKey, id, data string) (string, string) {
	t.Helper()
	c, err := client.Dial(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Send(frameSend(id, data)); err != nil {
		t.Fatal(err)
	}
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return string(f.Type), f.Error
}

// send is gated exactly like read: the first remote send is refused, the
// operator approves over unix, and the retry goes through.
func TestPreModeGatesSendLikeRead(t *testing.T) {
	unixEP, tlsEP, key, _ := startApprovalServer(t, "pre")
	info, err := client.Create(unixEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.CloseSession(unixEP, key, info.ID) }()

	typ, msg := sendOnce(t, tlsEP, key, info.ID, "echo hi\n")
	if typ != "error" || !strings.Contains(msg, "pending approval") {
		t.Fatalf("unapproved remote send must be gated, got %q %q", typ, msg)
	}

	if _, err := client.Approve(unixEP, key, info.ID); err != nil {
		t.Fatal(err)
	}
	typ, msg = sendOnce(t, tlsEP, key, info.ID, "echo hi\n")
	if typ == "error" && strings.Contains(msg, "pending approval") {
		t.Fatalf("approval was not honoured: %q", msg)
	}
	// The harness runs in-process PTYs, so the send itself is refused here.
	// Reaching that error is the point: the gate is no longer what stops it.
	if typ == "error" && !strings.Contains(msg, "not supported") {
		t.Fatalf("after approval, want the in-process refusal, got %q", msg)
	}
}

// read must stay gated the same way, so the two paths cannot drift apart.
func TestPreModeGatesReadAndSendAlike(t *testing.T) {
	unixEP, tlsEP, key, _ := startApprovalServer(t, "pre")
	info, err := client.Create(unixEP, key, client.CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.CloseSession(unixEP, key, info.ID) }()

	readErr := func() string {
		c, err := client.Dial(tlsEP, key)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.Send(frameRead(info.ID)); err != nil {
			t.Fatal(err)
		}
		f, err := c.Recv()
		if err != nil {
			t.Fatal(err)
		}
		return f.Error
	}
	if !strings.Contains(readErr(), "pending approval") {
		t.Fatalf("read must be gated, got %q", readErr())
	}
	_, sendMsg := sendOnce(t, tlsEP, key, info.ID, "echo hi\n")
	if !strings.Contains(sendMsg, "pending approval") {
		t.Fatalf("send must be gated the same way, got %q", sendMsg)
	}
}

// A successful send records a control event with the byte count and nothing
// from the terminal.
func TestAuditSendRecordsCountOnly(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	srv := &Server{cfg: Config{Audit: sink, ApprovalMode: "post"}}
	st := &connState{
		principal: &auth.Principal{Name: "laptop", Pub: priv.Public().(ed25519.PublicKey)},
		info:      transport.Info{Transport: transport.KindTLS, RemoteAddr: "10.0.0.9:5555"},
	}
	srv.auditSend(st, "sess1", 42)

	evs := sink.byKind(audit.KindSend)
	if len(evs) != 1 {
		t.Fatalf("got %d send events, want 1", len(evs))
	}
	e := evs[0]
	if e.Bytes != 42 {
		t.Fatalf("bytes = %d, want 42", e.Bytes)
	}
	if e.SessionID != "sess1" {
		t.Fatalf("session = %q", e.SessionID)
	}
	if e.Principal != "laptop" || e.RemoteAddr != "10.0.0.9:5555" {
		t.Fatalf("missing who/where: %+v", e)
	}
}
