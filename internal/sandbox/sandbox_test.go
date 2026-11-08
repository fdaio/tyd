package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	return dir
}

func TestNormalizeHost(t *testing.T) {
	s, err := Spec{}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsHost() {
		t.Fatalf("empty spec is not host: %+v", s)
	}
}

func TestNormalizeContainerDefaults(t *testing.T) {
	dir := tempDir(t)
	s, err := Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if s.Shell != DefaultShell {
		t.Errorf("shell = %q, want %q", s.Shell, DefaultShell)
	}
	if s.Network != "none" {
		t.Errorf("network = %q, want none", s.Network)
	}
	if s.Workdir != dir {
		t.Errorf("workdir = %q, want %q", s.Workdir, dir)
	}
}

func TestNormalizeRejections(t *testing.T) {
	dir := tempDir(t)
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"missing image", Spec{Backend: "docker", Workdir: dir}, "image"},
		{"dash image", Spec{Backend: "docker", Image: "-rf", Workdir: dir}, "'-'"},
		{"missing workdir", Spec{Backend: "docker", Image: "debian:bookworm"}, "workdir"},
		{"root workdir", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: "/"}, "filesystem root"},
		{"relative shell", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Shell: "sh"}, "absolute"},
		{"bad network", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Network: "slirp4netns"}, "network"},
		{"negative pids", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Pids: -1}, "negative"},
		{"bad memory", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Memory: "lots"}, "memory"},
		{"bad cpus", Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, CPUs: "many"}, "cpus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.spec.Normalize()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeNetworkPerBackend(t *testing.T) {
	dir := tempDir(t)
	if _, err := (Spec{Backend: "podman", Image: "debian:bookworm", Workdir: dir, Network: "slirp4netns"}).Normalize(); err != nil {
		t.Fatalf("podman slirp4netns: %v", err)
	}
	if _, err := (Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Network: "slirp4netns"}).Normalize(); err == nil {
		t.Fatal("docker accepted slirp4netns")
	}
	if _, err := (Spec{Backend: "podman", Image: "debian:bookworm", Workdir: dir, Network: "bridge"}).Normalize(); err == nil {
		t.Fatal("podman accepted bridge")
	}
}

func TestWithin(t *testing.T) {
	root := filepath.Clean("/work")
	for _, p := range []string{"/work", "/work/a", "/work/a/b", "/works"} {
		want := p == "/work" || p == "/work/a" || p == "/work/a/b"
		if got := Within(root, p); got != want {
			t.Errorf("Within(%q, %q) = %v, want %v", root, p, got, want)
		}
	}
	if Within(root, "/work/../etc") {
		t.Error("Within accepted a path that leaves the root")
	}
}

func TestResolveSession(t *testing.T) {
	dir := tempDir(t)
	s := Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Shell: "/bin/sh"}
	if shell, cwd, err := s.ResolveSession("", ""); err != nil || shell != "/bin/sh" || cwd != dir {
		t.Fatalf("defaults = %q %q %v", shell, cwd, err)
	}
	if _, _, err := s.ResolveSession("/bin/bash", ""); err == nil {
		t.Fatal("accepted a client-chosen shell")
	}
	if _, _, err := s.ResolveSession("", "/etc"); err == nil {
		t.Fatal("accepted a cwd outside the workdir")
	}
	sub := filepath.Join(dir, "sub")
	if shell, cwd, err := s.ResolveSession("", sub); err != nil || shell != "/bin/sh" || cwd != sub {
		t.Fatalf("subdir = %q %q %v", shell, cwd, err)
	}
}

func TestHostCommand(t *testing.T) {
	cmd, err := Spec{}.Command("/bin/sh", "/tmp", []string{"A=1"}, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/bin/sh" || cmd.Dir != "/tmp" || len(cmd.Env) != 1 || cmd.Env[0] != "A=1" {
		t.Fatalf("host command = %+v", cmd)
	}
}

func TestDockerCommand(t *testing.T) {
	dir := tempDir(t)
	s := Spec{Backend: "docker", Image: "debian:bookworm", Workdir: dir, Shell: "/bin/sh",
		Network: "none", Memory: "2g", CPUs: "2", Pids: 512}
	cmd, err := s.Command("/bin/sh", dir, []string{"TERM=xterm-256color", "TYD_SESSION=abc"}, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmd.Args, " ")
	for _, want := range []string{
		"run --rm -i", "--pull=never", "--network none", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--read-only", "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
		"--memory 2g", "--cpus 2", "--pids-limit 512",
		"-v " + dir + ":" + dir + ":rw", "-w " + dir,
		"--user 501:20", "-e HOME=/tmp", "-e TERM=xterm-256color", "-e TYD_SESSION=abc",
		"--entrypoint /bin/sh debian:bookworm",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("command missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--userns") {
		t.Errorf("docker command has a podman flag:\n%s", got)
	}
}

func TestPodmanCommandUsesKeepID(t *testing.T) {
	dir := tempDir(t)
	s := Spec{Backend: "podman", Image: "debian:bookworm", Workdir: dir, Shell: "/bin/sh", Network: "none"}
	cmd, err := s.Command("/bin/sh", dir, nil, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmd.Args, " ")
	if !strings.Contains(got, "--userns=keep-id") {
		t.Errorf("podman command has no --userns=keep-id:\n%s", got)
	}
	if strings.Contains(got, "--user ") {
		t.Errorf("podman command maps a user explicitly:\n%s", got)
	}
}

func TestResolveRejectsInvalidBackend(t *testing.T) {
	if _, err := Resolve("chroot"); err == nil {
		t.Fatal("accepted an unknown backend")
	}
	if got, err := Resolve(""); err != nil || got != "host" {
		t.Fatalf("empty = %q %v", got, err)
	}
}

func TestCheckHostIsNoop(t *testing.T) {
	if err := (Spec{}).Check(t.Context()); err != nil {
		t.Fatal(err)
	}
}
