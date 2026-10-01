package client

import (
	"net"
	"strings"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/transport"
)

// A client has to refuse a daemon it cannot speak before it signs anything. The
// signature is what an old peer and an impostor both fail at, so refusing later
// would still say "handshake failed" and leave the operator to guess which end
// to upgrade. It also has to happen before the key is used: a client that signs
// first and complains afterwards has already handed this key to whatever
// answered.

func TestClientRefusesADaemonItCannotSpeakBeforeSigning(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		want    string
	}{
		{
			// What a build from before the field existed sends: the field is
			// omitted, so the version arrives as zero.
			name:    "a daemon that sends no version",
			version: 0,
			want:    "daemon sends no handshake version, so it is older than version 1: upgrade the daemon",
		},
		{
			name:    "a daemon from the future",
			version: auth.CurrentVersion + 1,
			want:    "daemon speaks handshake version 2, this client speaks version 1: upgrade the daemon",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, key, err := auth.Generate()
			if err != nil {
				t.Fatal(err)
			}
			mine, peer := net.Pipe()
			defer mine.Close()
			defer peer.Close()

			nonce, err := auth.NewNonce()
			if err != nil {
				t.Fatal(err)
			}
			signed := make(chan bool, 1)
			go func() {
				if err := protocol.WriteFrame(peer, protocol.Frame{
					Type:    protocol.TypeChallenge,
					Version: tc.version,
					Data:    nonce,
				}); err != nil {
					signed <- false
					return
				}
				// Nothing should arrive. If a frame does, the client signed.
				peer.SetDeadline(time.Now().Add(250 * time.Millisecond))
				f, err := protocol.ReadFrame(peer)
				signed <- err == nil && f.Type == protocol.TypeAuth
			}()

			conn := &Conn{nc: transport.Wrap(mine, transport.Info{Transport: transport.KindUnix})}
			err = conn.AuthenticateBound(key, nil)
			if err == nil {
				t.Fatal("client accepted a daemon it cannot speak")
			}
			if got := err.Error(); got != tc.want {
				t.Errorf("error:\n got %q\nwant %q", got, tc.want)
			}
			if <-signed {
				t.Fatal("client signed for a daemon it had already refused")
			}
		})
	}
}

func TestClientNamesBothVersionsWhenItRefuses(t *testing.T) {
	// The whole reason for the field is that an operator can tell an old peer
	// from an impostor. Both numbers have to be in the text or the message is
	// the same one it replaced.
	_, key, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	mine, peer := net.Pipe()
	defer mine.Close()
	defer peer.Close()
	go func() {
		_ = protocol.WriteFrame(peer, protocol.Frame{
			Type:    protocol.TypeChallenge,
			Version: 99,
			Data:    make([]byte, auth.NonceSize),
		})
		// Hold the pipe open so the client has a daemon to read from, then let
		// the test's deferred close end it.
		time.Sleep(300 * time.Millisecond)
	}()
	conn := &Conn{nc: transport.Wrap(mine, transport.Info{Transport: transport.KindUnix})}
	err = conn.AuthenticateBound(key, nil)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"99", "1", "daemon", "upgrade"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not mention %q", msg, want)
		}
	}
}
