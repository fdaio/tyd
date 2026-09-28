package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"

	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/transport"
)

// End-to-end security for the relay path.
//
// The hub splices two WebSocket legs with io.Copy and never looks inside, so a
// session that runs the tyd protocol straight over that splice is readable by
// the relay and by Cloudflare in front of it, and accepts bytes injected from
// the middle. Both peers instead wrap their own leg in TLS and authenticate the
// result with an Ed25519 signature over the TLS exporter, so the relay ends up
// copying ciphertext it cannot read, and a relay that re-terminates TLS to
// impersonate one side is caught by the binding signature.
//
// The client's half lives in internal/client; this is the server's.

// AcceptE2E claims a ticket on the relay and returns the spliced leg secured by
// end-to-end TLS, plus the channel binding the auth response must cover.
func AcceptE2E(ctx context.Context, relayURL, ticket string, cert tls.Certificate, key ed25519.PrivateKey) (net.Conn, []byte, error) {
	conn, err := Accept(ctx, relayURL, ticket)
	if err != nil {
		return nil, nil, err
	}
	secure, binder, err := transport.ServerE2E(conn, transport.E2EServerConfig(cert))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	// The client verifies this before it authenticates, so it learns the peer
	// on the other end is the one it paired with and not a relay standing in.
	// No nonce: the exporter is already unique to this TLS session, and
	// replaying a binding within its own session proves nothing.
	if err := protocol.WriteFrame(secure, auth.BoundFrame(key, nil, binder)); err != nil {
		_ = secure.Close()
		return nil, nil, fmt.Errorf("relay e2e binding: %w", err)
	}
	return secure, binder, nil
}
