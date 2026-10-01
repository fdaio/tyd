package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tyd/internal/auth"
	"tyd/internal/client"
	"tyd/internal/mcp"
	"tyd/internal/server"
	"tyd/internal/session"
	"tyd/internal/transport"
)

// The alias is the one part of an open a model controls, and it can be refused. It
// used to be checked only after the session had been created on the target, so a
// refused open left a shell running that the model had been told did not exist —
// with nothing to close it, because the model never learned the id.
func TestARefusedAliasLeavesNoSessionBehind(t *testing.T) {
	// AF_UNIX allows about 104 bytes for the whole path, and a t.TempDir() path
	// under a long TMPDIR overruns it — the same limit docs/operations.md records
	// for a long HOME. The socket needs a short directory; the rest does not.
	dir := t.TempDir()
	short := remoteShortDir(t)
	liveRoot := filepath.Join(short, "live")
	t.Cleanup(func() { killLiveAgents(liveRoot) })

	mgr := session.NewManager()
	mgr.ConfigureLive(liveRoot, os.Args[0])
	mgr.SetStarter(testLiveStarter)

	key, trust, err := auth.NewAdminStore()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(short, "t.sock")
	srv := server.NewWithConfig(server.Config{
		Socket: sock, Listen: "off", DataListen: "off",
		CertPath: filepath.Join(dir, "server.crt"), KeyPath: filepath.Join(dir, "server.key"),
		Mgr: mgr, Trust: trust, ApprovalMode: "post",
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := client.WaitReady(client.Endpoint{Kind: transport.KindUnix, Address: sock}, 5e9); err != nil {
		t.Fatal(err)
	}

	opts := archiveOpts(t)
	opts.socket = sock
	opts.identity = filepath.Join(dir, "id_ed25519")
	b := newMCPBackend(opts, key, []mcpTarget{{label: "local"}})

	// The daemon's own view of what it has, so the assertion is about the target
	// rather than about anything this process remembers.
	onDaemon := func() int { return len(mgr.List()) }
	if n := onDaemon(); n != 0 {
		t.Fatalf("fixture already has %d session(s)", n)
	}

	// A name that substitutes when pasted into a shell.
	if _, err := b.Open(t.Context(), mcp.OpenRequest{Name: "a`id`"}); err == nil {
		t.Fatal("an executable alias was accepted")
	}
	if n := onDaemon(); n != 0 {
		t.Fatalf("a refused alias left %d session(s) running on the target", n)
	}

	// And an accepted alias still opens, so the check is not simply refusing
	// everything.
	opened, err := b.Open(t.Context(), mcp.OpenRequest{Name: "build"})
	if err != nil {
		t.Fatalf("a valid alias was refused: %v", err)
	}
	if !strings.Contains(opened.HumanAttach, "build") {
		t.Errorf("takeover command %q does not name the alias", opened.HumanAttach)
	}
	if n := onDaemon(); n != 1 {
		t.Fatalf("a valid alias left %d session(s), want 1", n)
	}
}
