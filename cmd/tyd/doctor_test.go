package main

import (
	"crypto/ed25519"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tyd/internal/auth"
	"tyd/internal/controlpanel"
	"tyd/internal/live"
	"tyd/internal/peers"
)

func doctorOpts(t *testing.T, dir string) options {
	t.Helper()
	return options{
		cmd:      "doctor",
		identity: filepath.Join(dir, "id_ed25519"),
		trust:    filepath.Join(dir, "trusted.json"),
		peers:    filepath.Join(dir, "peers.json"),
		aliases:  filepath.Join(dir, "aliases.json"),
		sessions: filepath.Join(dir, "sessions.json"),
		recent:   filepath.Join(dir, "recent.json"),
		// A temp dir under macOS is long enough to overrun AF_UNIX, which
		// would fail the socket path check for reasons unrelated to health.
		live: shortLiveRoot(t),
	}
}

func findCheck(t *testing.T, checks []check, name string) check {
	t.Helper()
	for _, c := range checks {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, checks)
	return check{}
}

func TestDoctorFlagsTruncatedPeersFile(t *testing.T) {
	dir := t.TempDir()
	opts := doctorOpts(t, dir)
	if _, _, err := auth.EnsureIdentity(opts.identity, opts.trust); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.peers, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	checks, fixable := doctorChecks(opts)
	if !fixable {
		t.Fatal("an empty peers.json should be reported as fixable")
	}
	c := findCheck(t, checks, "peers")
	if c.level != levelFail || !strings.Contains(c.detail, "empty") {
		t.Fatalf("peers check = %+v", c)
	}
	if got := findCheck(t, checks, "identity"); got.level != levelOK {
		t.Fatalf("identity check = %+v", got)
	}
	if got := findCheck(t, checks, "writable"); got.level != levelOK {
		t.Fatalf("writable check = %+v", got)
	}
}

func TestDoctorHealthyStatePasses(t *testing.T) {
	dir := t.TempDir()
	opts := doctorOpts(t, dir)
	key, _, err := auth.EnsureIdentity(opts.identity, opts.trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.WriteBootstrapTrust(opts.trust, "me", key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := peers.Save(opts.peers, &peers.File{
		Registration: &peers.Registration{ID: "d1", PublicKey: auth.EncodePublic(key.Public().(ed25519.PublicKey))},
	}); err != nil {
		t.Fatal(err)
	}

	checks, fixable := doctorChecks(opts)
	if fixable {
		t.Fatal("healthy state needs no fix")
	}
	for _, c := range checks {
		if c.level == levelFail {
			t.Fatalf("unexpected failure: %+v", c)
		}
	}
}

// shortLiveRoot gives each test its own live root that is still short enough
// to bind a socket. A t.TempDir path under macOS overruns AF_UNIX, and a
// shared path would inherit another run's leftovers.
func shortLiveRoot(t *testing.T) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(os.TempDir(), "tq"), 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := os.MkdirTemp(filepath.Join(os.TempDir(), "tq"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "l")
}

// A long HOME overruns the AF_UNIX limit. The agent would otherwise fail to
// connect with "invalid argument", so doctor has to name the path and the
// limit instead.
func TestDoctorReportsLongLiveSocketPath(t *testing.T) {
	opts := doctorOpts(t, t.TempDir())
	opts.live = filepath.Join("/", strings.Repeat("long-home-directory", 6), "live")
	checks, _ := doctorChecks(opts)
	for _, c := range checks {
		if c.name != "live socket path" {
			continue
		}
		if c.level != levelFail {
			t.Fatalf("a %d byte socket path should fail, got %+v", len(live.SockPath(live.Dir(opts.live, "0123456789abcdef"))), c)
		}
		for _, want := range []string{"limit is", "HOME"} {
			if !strings.Contains(c.detail, want) {
				t.Fatalf("detail should mention %q, got %q", want, c.detail)
			}
		}
		return
	}
	t.Fatal("doctor did not check the live socket path")
}

// --fix sets the damaged file aside and rebuilds it from the CP, without
// stating an approval mode, so a pre daemon does not come back as full.
func TestDoctorFixRebuildsFromControlPanel(t *testing.T) {
	dir := t.TempDir()
	opts := doctorOpts(t, dir)
	opts.fix = true
	key, _, err := auth.EnsureIdentity(opts.identity, opts.trust)
	if err != nil {
		t.Fatal(err)
	}
	pub := auth.EncodePublic(key.Public().(ed25519.PublicKey))

	svc := controlpanel.New()
	reg, err := svc.Register(controlpanel.RegisterRequest{PublicKey: pub, ApprovalMode: controlpanel.ApprovalPre})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	opts.platform = srv.URL

	if err := os.WriteFile(opts.peers, []byte(`{"broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runDoctor(opts); err != nil {
		t.Fatalf("doctor --fix: %v", err)
	}

	got, err := peers.Load(opts.peers)
	if err != nil {
		t.Fatalf("rebuilt peers.json does not load: %v", err)
	}
	if got.Registration == nil || got.Registration.ID != reg.ID {
		t.Fatalf("registration = %+v want id %s", got.Registration, reg.ID)
	}
	if got.Registration.ApprovalMode != controlpanel.ApprovalPre {
		t.Fatalf("approval mode came back as %q; recovery must not relax it", got.Registration.ApprovalMode)
	}

	matches, err := filepath.Glob(opts.peers + ".corrupt.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("damaged file not kept: %v", matches)
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"broken` {
		t.Fatalf("quarantined content = %q", b)
	}
}

func TestDoctorReportsOutputLogFailure(t *testing.T) {
	dir := t.TempDir()
	opts := doctorOpts(t, dir)
	if _, _, err := auth.EnsureIdentity(opts.identity, opts.trust); err != nil {
		t.Fatal(err)
	}
	sess := filepath.Join(opts.live, "abcd1234abcd1234")
	if err := live.SaveMeta(sess, live.Meta{ID: "abcd1234abcd1234", Owner: "t", Shell: "/bin/sh"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live.OutputErrPath(sess), []byte("no space left on device\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, _ := doctorChecks(opts)
	c := findCheck(t, checks, "output log")
	if c.level != levelFail || !strings.Contains(c.detail, "no space") {
		t.Fatalf("output log check = %+v", c)
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tt := range []struct {
		in   uint64
		want string
	}{
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{5 << 20, "5.0 MiB"},
		{3 << 30, "3.0 GiB"},
	} {
		if got := humanBytes(tt.in); got != tt.want {
			t.Fatalf("humanBytes(%d) = %s want %s", tt.in, got, tt.want)
		}
	}
}
