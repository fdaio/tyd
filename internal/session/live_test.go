package session

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"tyd/internal/auth"
	"tyd/internal/live"
)

func TestMain(m *testing.M) {
	if os.Getenv("TYD_TEST_LIVE_AGENT") == "1" {
		dir := os.Getenv("TYD_TEST_LIVE_DIR")
		// Empty unless a test asks for a ceiling, so these harnesses keep meaning
		// "no file root" rather than silently gaining one.
		if err := live.Run(dir, live.Config{FileRoot: os.Getenv("TYD_TEST_LIVE_FILE_ROOT")}); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testLiveStarter(t *testing.T) live.Starter {
	t.Helper()
	return func(_, dir, fileRoot string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(),
			"TYD_TEST_LIVE_AGENT=1",
			"TYD_TEST_LIVE_DIR="+dir,
			// Forwarded so a test that configures a ceiling gets a real agent with
			// one, rather than only ever exercising the no-root path.
			"TYD_TEST_LIVE_FILE_ROOT="+fileRoot,
		)
		logf, err := os.OpenFile(live.LogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		cmd.Stdout = logf
		cmd.Stderr = logf
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			_ = logf.Close()
			return nil, err
		}
		_ = logf.Close()
		return cmd, nil
	}
}

func TestLivePersistAcrossManagerRestart(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })
	marker := filepath.Join(cwd, "alive")

	_, priv, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ownerPub := auth.EncodePublic(priv.Public().(ed25519.PublicKey))

	m1 := NewManager()
	m1.ConfigureLive(root, "")
	m1.SetStarter(testLiveStarter(t))

	s, err := m1.Create(CreateOpts{
		Shell:    "/bin/sh",
		Cwd:      cwd,
		Owner:    "tester",
		OwnerPub: ownerPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := s.ID

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	// Avoid matching PTY echo of the typed command: wait on a side-effect file.
	if _, err := att.Write([]byte("touch '" + marker + "'\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("shell did not create marker: %v", err)
	}
	att.Detach()

	// Graceful daemon stop: release without killing the agent.
	m1.Shutdown()

	if !live.Alive(live.Dir(root, sid)) {
		t.Fatal("live-agent died after Shutdown")
	}

	m2 := NewManager()
	m2.ConfigureLive(root, "")
	m2.SetStarter(testLiveStarter(t))
	restored, err := m2.RestoreLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].Session.ID != sid {
		t.Fatalf("restore=%v want id %s", restored, sid)
	}
	if restored[0].OwnerPub != ownerPub {
		t.Fatalf("owner pub %q", restored[0].OwnerPub)
	}

	trust := auth.NewStore()
	p := trust.EnsurePeer("tester", priv.Public().(ed25519.PublicKey), nil)
	if err := trust.Grant(priv.Public().(ed25519.PublicKey), sid, auth.OwnerCaps...); err != nil {
		t.Fatal(err)
	}
	if !trust.Allow(p, auth.CapAttach, sid) {
		t.Fatal("caps not restored")
	}

	s2, err := m2.Get(sid)
	if err != nil {
		t.Fatal(err)
	}
	att2, _, err := s2.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker2 := filepath.Join(cwd, "alive2")
	if _, err := att2.Write([]byte("touch '" + marker2 + "'\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker2); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker2); err != nil {
		t.Fatalf("reattach shell did not create marker: %v", err)
	}
	att2.Detach()

	if err := m2.Close(sid); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && live.Alive(live.Dir(root, sid)) {
		time.Sleep(50 * time.Millisecond)
	}
	if live.Alive(live.Dir(root, sid)) {
		t.Fatal("agent still alive after Close")
	}
}

func TestLiveDeadAgentCleanedOnRestore(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dir := live.Dir(root, "deadbeef")
	if err := live.SaveMeta(dir, live.Meta{
		ID:        "deadbeef",
		Owner:     "x",
		OwnerPub:  "yw==",
		Shell:     "/bin/sh",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Rows:      24,
		Cols:      80,
	}); err != nil {
		t.Fatal(err)
	}
	if err := live.WritePID(live.AgentPIDPath(dir), 1<<30); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	m.ConfigureLive(root, "")
	restored, err := m.RestoreLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 0 {
		t.Fatalf("want no restore, got %d", len(restored))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dead dir should be removed: %v", err)
	}
}

func TestInProcessCreateStillWorks(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att.Detach()
	if _, err := att.Write([]byte("echo HI\n")); err != nil {
		t.Fatal(err)
	}
	var got []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := att.RecvTimeout(100 * time.Millisecond)
		if err == nil {
			got = append(got, b...)
			if strings.Contains(string(got), "HI") {
				return
			}
			continue
		}
		if !os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
	t.Fatalf("got %q", got)
}

func TestInProcessReadUnsupported(t *testing.T) {
	m := NewManager()
	defer m.CloseAll()
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Read(0, 0, 0, live.ReadConditions{})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("want unsupported, got %v", err)
	}
}

func TestLiveReadResume(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	m := liveManager(t, root)
	defer m.CloseAll()
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker := "read-resume-ok"
	if _, err := att.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		b, err := att.RecvTimeout(100 * time.Millisecond)
		if err == nil {
			got = append(got, b...)
			if strings.Contains(string(got), marker) {
				break
			}
			continue
		}
		if !os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
	if !strings.Contains(string(got), marker) {
		t.Fatalf("no marker in attach stream: %q", got)
	}

	first, err := s.Read(0, 0, 0, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Dropped != 0 {
		t.Fatalf("dropped=%d", first.Dropped)
	}
	if !strings.Contains(string(first.Data), marker) {
		t.Fatalf("read missing marker: %q", first.Data)
	}
	second, err := s.Read(first.CursorNext, first.Epoch, 0, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	all := append(append([]byte(nil), first.Data...), second.Data...)
	if !strings.Contains(string(all), marker) {
		t.Fatalf("paged read lost marker")
	}

	more := "read-page-two"
	if _, err := att.Write([]byte("echo " + more + "\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := att.RecvTimeout(100 * time.Millisecond)
		if err == nil {
			got = append(got, b...)
			if strings.Contains(string(got), more) {
				break
			}
			continue
		}
		if !os.IsTimeout(err) {
			t.Fatal(err)
		}
	}
	third, err := s.Read(first.CursorNext, first.Epoch, 0, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(third.Data), more) {
		t.Fatalf("resume from cursor_next missed new output: %q", third.Data)
	}
	att.Detach()

	dir := live.Dir(root, s.ID)
	live.KillAgent(dir)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.State() == StateExited {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	att2, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	defer att2.Detach()
	after, err := s.Read(0, 0, 0, live.ReadConditions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after.Data), marker) {
		t.Fatalf("seq reset after respawn: %q", after.Data)
	}
}

// liveManager builds a manager whose live-agents are real subprocesses.
func liveManager(t *testing.T, root string) *Manager {
	t.Helper()
	m := NewManager()
	m.ConfigureLive(root, "")
	m.SetStarter(testLiveStarter(t))
	return m
}

// waitStreamEnd drains an attachment until its stream ends.
func waitStreamEnd(t *testing.T, att *Attachment) []byte {
	t.Helper()
	acc := []byte{}
	for {
		b, err := att.RecvTimeout(10 * time.Second)
		if err != nil {
			return acc
		}
		acc = append(acc, b...)
	}
}

func TestLiveShellExitKeepsSession(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })

	m := liveManager(t, root)
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: cwd, Owner: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dir := live.Dir(root, s.ID)

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	before := filepath.Join(cwd, "before-exit")
	if _, err := att.Write([]byte("touch '" + before + "'\n")); err != nil {
		t.Fatal(err)
	}
	waitFile(t, before)
	if _, err := att.Write([]byte("exit 0\n")); err != nil {
		t.Fatal(err)
	}

	acc := waitStreamEnd(t, att)
	if !strings.Contains(string(acc), "shell exited (status 0)") {
		t.Fatalf("missing exit notice: %q", acc)
	}
	if !att.ShellExited() {
		t.Fatal("attachment should report a shell exit")
	}
	if att.SessionClosed() {
		t.Fatal("session must stay open after the shell exits")
	}
	if got := s.State(); got != StateExited {
		t.Fatalf("state=%s want EXITED", got)
	}
	if !live.Alive(dir) {
		t.Fatal("agent should outlive its shell")
	}
	if live.ShellAlive(dir) {
		t.Fatal("shell pid file should be gone")
	}
	if s.IdleSince().IsZero() {
		t.Fatal("exited session should be idle")
	}

	// Re-attaching starts a new shell in the same session and replays history.
	att2, snap, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snap), "shell exited (status 0)") {
		t.Fatalf("replay lost the exit notice: %q", snap)
	}
	if !live.ShellAlive(dir) {
		t.Fatal("reattach should have started a shell")
	}
	after := filepath.Join(cwd, "after-exit")
	if _, err := att2.Write([]byte("touch '" + after + "'\n")); err != nil {
		t.Fatal(err)
	}
	waitFile(t, after)
	if got := s.State(); got != StateAttached {
		t.Fatalf("state=%s want ATTACHED", got)
	}
	att2.Detach()

	// A watch on the exited session reports the exit instead of hanging.
	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	waitAgentGone(t, dir)
}

func TestLiveExitedSessionWatchEnds(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })

	m := liveManager(t, root)
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: cwd, Owner: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dir := live.Dir(root, s.ID)
	t.Cleanup(func() { _ = m.Close(s.ID) })

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := att.Write([]byte("exit 7\n")); err != nil {
		t.Fatal(err)
	}
	waitStreamEnd(t, att)

	w, snap, err := s.Watch()
	if err != nil {
		t.Fatal(err)
	}
	acc := append([]byte(nil), snap...)
	for {
		b, err := w.RecvTimeout(10 * time.Second)
		if err != nil {
			break
		}
		acc = append(acc, b...)
	}
	if !strings.Contains(string(acc), "shell exited (status 7)") {
		t.Fatalf("watch missed the notice: %q", acc)
	}
	if !w.ShellExited() {
		t.Fatal("watcher should report a shell exit")
	}
	if w.SessionClosed() {
		t.Fatal("watcher must not report a closed session")
	}
	if !live.Alive(dir) {
		t.Fatal("agent should survive")
	}
}

func TestLiveExitedSessionRestoredAndReattached(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })

	m1 := liveManager(t, root)
	s, err := m1.Create(CreateOpts{Shell: "/bin/sh", Cwd: cwd, Owner: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := att.Write([]byte("exit 0\n")); err != nil {
		t.Fatal(err)
	}
	waitStreamEnd(t, att)
	m1.Shutdown()

	m2 := liveManager(t, root)
	restored, err := m2.RestoreLive()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 {
		t.Fatalf("restore=%v", restored)
	}
	s2, err := m2.Get(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.State(); got != StateExited {
		t.Fatalf("restored state=%s want EXITED", got)
	}
	// The restored, shell-less session still gets a working shell.
	att2, _, err := s2.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(cwd, "after-restore")
	if _, err := att2.Write([]byte("touch '" + marker + "'\n")); err != nil {
		t.Fatal(err)
	}
	waitFile(t, marker)
	att2.Detach()
	if err := m2.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	waitAgentGone(t, live.Dir(root, s.ID))
}

func TestLiveExitedAgentRespawnedWhenLost(t *testing.T) {
	root, err := os.MkdirTemp("", "tl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cwd, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cwd) })

	m := liveManager(t, root)
	s, err := m.Create(CreateOpts{Shell: "/bin/sh", Cwd: cwd, Owner: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dir := live.Dir(root, s.ID)
	// Simulate an agent that dies without the session being closed.
	live.KillAgent(dir)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.State() != StateExited {
		time.Sleep(20 * time.Millisecond)
	}
	if got := s.State(); got != StateExited {
		t.Fatalf("state=%s want EXITED after the agent died", got)
	}

	att, _, err := s.Attach()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(cwd, "after-respawn")
	if _, err := att.Write([]byte("touch '" + marker + "'\n")); err != nil {
		t.Fatal(err)
	}
	waitFile(t, marker)
	att.Detach()
	if err := m.Close(s.ID); err != nil {
		t.Fatal(err)
	}
	waitAgentGone(t, dir)
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("shell never created %s", path)
}

func waitAgentGone(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !live.Alive(dir) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("agent still alive")
}
