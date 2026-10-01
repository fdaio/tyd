package server

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"tyd/internal/audit"
	"tyd/internal/auth"
	"tyd/internal/protocol"
	"tyd/internal/transport"
)

// The daemon refuses a client it cannot speak before it verifies anything.
// Verification is the only thing that fails identically for an old client and
// for an impostor, so checking after it would leave the operator with the same
// message either way. Checking first also means a client with a revoked or
// unknown key gets the version refusal rather than a different failure, so the
// two cannot be told apart by an attacker choosing which one to provoke.

// signedByAdmin builds an auth frame that would verify, so a refusal cannot be
// blamed on the key. Only the version is wrong.
func TestDaemonRefusesAClientItCannotSpeakBeforeVerifying(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		want    string
	}{
		{
			// What a build from before the field existed sends: the field is
			// omitted, so the version arrives as zero.
			name:    "a client that sends no version",
			version: 0,
			want:    "client sends no handshake version, so it is older than version 1: upgrade the client",
		},
		{
			name:    "a client from the future",
			version: auth.CurrentVersion + 1,
			want:    "client speaks handshake version 2, this daemon speaks version 1: upgrade the client",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, _, admin, getAudits := startApprovalServer(t, "post")

			nc, err := transport.DialUnix(ep.Address)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			nc.SetDeadline(time.Now().Add(5 * time.Second))

			chal, err := protocol.ReadFrame(nc)
			if err != nil {
				t.Fatal(err)
			}
			if chal.Version != auth.CurrentVersion {
				t.Errorf("challenge carries version %d, want %d", chal.Version, auth.CurrentVersion)
			}
			nonce, err := auth.NewNonce()
			if err != nil {
				t.Fatal(err)
			}
			f := auth.AuthFrameBound(admin, nonce, nil)
			f.Version = tc.version
			if err := protocol.WriteFrame(nc, f); err != nil {
				t.Fatal(err)
			}

			resp, err := protocol.ReadFrame(nc)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Type != protocol.TypeError {
				t.Fatalf("expected a refusal, got %q", resp.Type)
			}
			if resp.Error != tc.want {
				t.Errorf("refusal:\n got %q\nwant %q", resp.Error, tc.want)
			}
			if !hasKind(getAudits(), audit.KindDenied) {
				t.Error("a refused handshake left no record of the denial")
			}
			// The operator reads the audit, not the client's error, so the
			// version has to be in the record too.
			if !auditReasonNamesVersion(getAudits(), tc.version) {
				t.Errorf("the audit does not record the refused version %d: %+v",
					tc.version, getAudits())
			}
		})
	}
}

// An unauthenticated connection is refused on the same path, so it must still
// not be mistaken for a version failure.
func TestDaemonStillRefusesAnUnauthenticatedFrame(t *testing.T) {
	ep, _, _, _ := startApprovalServer(t, "post")
	nc, err := net.Dial("unix", ep.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := protocol.ReadFrame(nc); err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(nc, protocol.Frame{Type: protocol.TypeStatus, Version: auth.CurrentVersion}); err != nil {
		t.Fatal(err)
	}
	resp, err := protocol.ReadFrame(nc)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("expected a refusal, got %q", resp.Type)
	}
}

// hasKind reports whether any recorded event has this kind. The existing helper
// matches on session as well, and a handshake denial has no session.
func hasKind(events []audit.Event, kind audit.Kind) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// auditReasonNamesVersion reports whether a denial recorded the version it
// refused, which is the number the operator needs to know what to upgrade.
func auditReasonNamesVersion(events []audit.Event, version int) bool {
	for _, e := range events {
		if e.Kind != audit.KindDenied {
			continue
		}
		if strings.Contains(e.Reason, fmt.Sprintf("version %d", version)) {
			return true
		}
	}
	return false
}
