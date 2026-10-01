package auth

import (
	"strings"
	"testing"
)

// The version range is the whole contract: one accepted value, everything else
// refused with a message that names both sides. A check that quietly accepted a
// wider range would be a downgrade attack, so the boundaries are asserted
// rather than described.

func TestCheckVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		self    string
		peer    string
		version int
		wantErr bool
		want    []string
	}{
		{
			name:    "the current version",
			self:    "client",
			peer:    "daemon",
			version: CurrentVersion,
		},
		{
			// Zero is what a build from before the field existed sends, and a
			// negative is not a version at all.
			name:    "no version at all",
			self:    "client",
			peer:    "daemon",
			version: 0,
			wantErr: true,
			want:    []string{"daemon", "no handshake version", "upgrade the daemon"},
		},
		{
			name:    "a negative version",
			self:    "daemon",
			peer:    "client",
			version: -1,
			wantErr: true,
			want:    []string{"client", "upgrade the client"},
		},
		{
			name:    "a peer one version ahead",
			self:    "client",
			peer:    "daemon",
			version: CurrentVersion + 1,
			wantErr: true,
			want:    []string{"daemon", "upgrade the daemon"},
		},
		{
			name:    "a peer far ahead",
			self:    "daemon",
			peer:    "client",
			version: 99,
			wantErr: true,
			// Both numbers have to be here, or the message is no better than
			// the "handshake failed" it replaces.
			want: []string{"client", "99", "daemon", "1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckVersion(tc.self, tc.peer, tc.version)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted version %d", tc.version)
				}
				for _, want := range tc.want {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal %q does not mention %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("refused version %d: %v", tc.version, err)
			}
		})
	}
}

// Both handshake frames carry the version, because either one arriving without it
// is what an unversioned peer looks like.
func TestHandshakeFramesCarryTheVersion(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if got := ChallengeFrame(nonce).Version; got != CurrentVersion {
		t.Errorf("challenge carries version %d, want %d", got, CurrentVersion)
	}
	if got := AuthFrameBound(priv, nonce, nil).Version; got != CurrentVersion {
		t.Errorf("auth frame carries version %d, want %d", got, CurrentVersion)
	}
	// AuthFrame is the unbound form and is used by the unix path, so it has to
	// carry it too.
	if got := AuthFrame(priv, nonce).Version; got != CurrentVersion {
		t.Errorf("unbound auth frame carries version %d, want %d", got, CurrentVersion)
	}
}
