package server

import (
	"net"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/session"
)

func TestHandshakeTimeoutClosesSilentConnection(t *testing.T) {
	_, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(Config{
		Trust:            trust,
		Mgr:              session.NewManager(),
		HandshakeTimeout: 50 * time.Millisecond,
	})
	srv, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handle(srv, nil, false)
		close(done)
	}()

	f, err := protocol.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeChallenge {
		t.Fatalf("first frame = %q, want challenge", f.Type)
	}
	// Do not answer. The deadline must end the exchange even though the test
	// never reads the error frame.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a silent connection was not closed by the handshake deadline")
	}
	_ = client.Close()
}

func TestConnectionCapRefusesTheNextHandshake(t *testing.T) {
	_, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(Config{
		Trust:            trust,
		Mgr:              session.NewManager(),
		HandshakeTimeout: time.Second,
		MaxConns:         1,
	})
	srv1, client1 := net.Pipe()
	go s.handle(srv1, nil, false)
	if f, err := protocol.ReadFrame(client1); err != nil || f.Type != protocol.TypeChallenge {
		t.Fatalf("first connection did not start a handshake: %+v %v", f, err)
	}

	srv2, client2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handle(srv2, nil, false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a connection over the cap was not closed")
	}
	_ = client1.Close()
	_ = client2.Close()
}
