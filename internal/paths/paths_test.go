package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSocketUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := DefaultSocket()
	want := filepath.Join(home, ".tyd", "tyd.sock")
	if got != want {
		t.Fatalf("DefaultSocket() = %q, want %q", got, want)
	}
	if DefaultIdentity() != filepath.Join(home, ".tyd", "id_ed25519") {
		t.Fatalf("identity %q", DefaultIdentity())
	}
	if DefaultTrust() != filepath.Join(home, ".tyd", "trusted.json") {
		t.Fatalf("trust %q", DefaultTrust())
	}
	if DefaultPeers() != filepath.Join(home, ".tyd", "peers.json") {
		t.Fatalf("peers %q", DefaultPeers())
	}
	if DefaultRecent() != filepath.Join(home, ".tyd", "recent.json") {
		t.Fatalf("recent %q", DefaultRecent())
	}
	if DefaultAliases() != filepath.Join(home, ".tyd", "aliases.json") {
		t.Fatalf("aliases %q", DefaultAliases())
	}
	if DefaultSessions() != filepath.Join(home, ".tyd", "sessions.json") {
		t.Fatalf("sessions %q", DefaultSessions())
	}
	if DefaultListen() != "off" {
		t.Fatalf("listen %q", DefaultListen())
	}
	if DefaultPlatform() != "https://app.getfda.dev" {
		t.Fatalf("platform %q", DefaultPlatform())
	}
	if DefaultAdvertise() != "" {
		t.Fatalf("advertise default %q, want empty", DefaultAdvertise())
	}
	if DefaultServerCert() != filepath.Join(home, ".tyd", "server.crt") {
		t.Fatalf("cert %q", DefaultServerCert())
	}
}

func TestDefaultSocketFallsBackWhenHomeMissing(t *testing.T) {
	t.Setenv("HOME", "")
	got := DefaultSocket()
	if got == "" {
		t.Fatal("empty socket path")
	}
	if filepath.Base(got) != "tyd.sock" {
		t.Fatalf("got %q, want a tyd.sock path", got)
	}
	if _, err := os.UserHomeDir(); err != nil {
		want := filepath.Join(os.TempDir(), ".tyd", "tyd.sock")
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}
