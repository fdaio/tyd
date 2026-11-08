// Package sandbox builds the process a session shell runs in.
//
// The daemon, live agents, keys, socket, and audit log stay on the host. A
// container backend only changes where the shell itself runs: the live agent
// still owns the PTY and the session state.
package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultShell is the shell a container session runs when the operator did not
// choose one. It must exist in the image.
const DefaultShell = "/bin/sh"

// Spec is the operator's session-runtime policy, carried from `tyd up` into
// each live agent through meta.json.
type Spec struct {
	Backend string `json:"backend,omitempty"` // host, docker, or podman
	Image   string `json:"image,omitempty"`
	Workdir string `json:"workdir,omitempty"`
	Shell   string `json:"shell,omitempty"`
	Network string `json:"network,omitempty"`
	Memory  string `json:"memory,omitempty"`
	CPUs    string `json:"cpus,omitempty"`
	Pids    int    `json:"pids,omitempty"`
}

// IsHost reports whether sessions run directly on the host.
func (s Spec) IsHost() bool {
	b := strings.TrimSpace(s.Backend)
	return b == "" || b == "host"
}

// Resolve turns the --sandbox value into a backend name. "auto" prefers podman
// because it is the rootless default on Linux; docker is the fallback.
func Resolve(backend string) (string, error) {
	b := strings.ToLower(strings.TrimSpace(backend))
	switch b {
	case "", "host":
		return "host", nil
	case "auto":
		for _, name := range []string{"podman", "docker"} {
			if _, err := exec.LookPath(name); err == nil {
				return name, nil
			}
		}
		return "", fmt.Errorf("--sandbox auto: neither podman nor docker is in PATH")
	case "podman", "docker":
		if _, err := exec.LookPath(b); err != nil {
			return "", fmt.Errorf("--sandbox %s: %w", b, err)
		}
		return b, nil
	default:
		return "", fmt.Errorf("--sandbox %q: want host, auto, docker, or podman", backend)
	}
}

// Normalize validates the spec and fills the defaults that do not depend on
// the host. It returns a copy so callers keep the operator's raw values.
func (s Spec) Normalize() (Spec, error) {
	if s.IsHost() {
		s.Backend = "host"
		return s, nil
	}
	if s.Backend != "docker" && s.Backend != "podman" {
		return Spec{}, fmt.Errorf("sandbox backend %q: want host, docker, or podman", s.Backend)
	}
	if strings.TrimSpace(s.Image) == "" {
		return Spec{}, fmt.Errorf("--sandbox-image is required for %s", s.Backend)
	}
	if strings.HasPrefix(s.Image, "-") {
		return Spec{}, fmt.Errorf("--sandbox-image %q: an image must not start with '-'", s.Image)
	}
	if strings.TrimSpace(s.Workdir) == "" {
		return Spec{}, fmt.Errorf("--sandbox-workdir is required for %s", s.Backend)
	}
	abs, err := filepath.Abs(s.Workdir)
	if err != nil {
		return Spec{}, fmt.Errorf("--sandbox-workdir %s: %w", s.Workdir, err)
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) {
		return Spec{}, fmt.Errorf("--sandbox-workdir %s: the filesystem root is refused", s.Workdir)
	}
	if strings.Contains(abs, ":") {
		return Spec{}, fmt.Errorf("--sandbox-workdir %s: a ':' cannot be represented in a container mount", s.Workdir)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Spec{}, fmt.Errorf("--sandbox-workdir %s: %w", s.Workdir, err)
	}
	if !info.IsDir() {
		return Spec{}, fmt.Errorf("--sandbox-workdir %s: not a directory", s.Workdir)
	}
	s.Workdir = abs

	if s.Shell == "" {
		s.Shell = DefaultShell
	}
	if !filepath.IsAbs(s.Shell) {
		return Spec{}, fmt.Errorf("--sandbox-shell %q must be an absolute path", s.Shell)
	}
	if s.Network == "" {
		s.Network = "none"
	}
	allowed := map[string]bool{"none": true, "host": true}
	if s.Backend == "podman" {
		allowed["slirp4netns"] = true
	} else {
		allowed["bridge"] = true
	}
	if !allowed[s.Network] {
		names := make([]string, 0, len(allowed))
		for name := range allowed {
			names = append(names, name)
		}
		return Spec{}, fmt.Errorf("--sandbox-network %q: not valid for %s (use one of %s)",
			s.Network, s.Backend, strings.Join(names, ", "))
	}
	if s.Pids < 0 {
		return Spec{}, fmt.Errorf("--sandbox-pids %d: must not be negative", s.Pids)
	}
	if s.Memory != "" && !memoryRE.MatchString(s.Memory) {
		return Spec{}, fmt.Errorf("--sandbox-memory %q: want a size such as 512m or 2g", s.Memory)
	}
	if s.CPUs != "" && !cpusRE.MatchString(s.CPUs) {
		return Spec{}, fmt.Errorf("--sandbox-cpus %q: want a number such as 1 or 1.5", s.CPUs)
	}
	return s, nil
}

var (
	memoryRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[bkmgBKMG]?$`)
	cpusRE   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

// Check confirms the runtime answers and the image is already present. It does
// not pull: a daemon that silently pulls an image on start is a daemon that
// reaches the network when the operator did not ask it to.
func (s Spec) Check(ctx context.Context) error {
	if s.IsHost() {
		return nil
	}
	if _, err := exec.LookPath(s.Backend); err != nil {
		return fmt.Errorf("sandbox runtime: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, s.Backend, "info").CombinedOutput(); err != nil {
		return fmt.Errorf("%s info: %v: %s", s.Backend, err, strings.TrimSpace(string(out)))
	}
	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, s.Backend, "image", "inspect", s.Image).CombinedOutput(); err != nil {
		return fmt.Errorf("image %q is not available locally (%v): %s; pull it first: %s pull %s",
			s.Image, err, strings.TrimSpace(string(out)), s.Backend, s.Image)
	}
	return nil
}

// ResolveSession applies the operator's policy to the shell and directory a
// client asked for. In a container the shell comes from the operator and the
// directory must stay inside the mounted workdir; a peer cannot widen either.
func (s Spec) ResolveSession(shell, cwd string) (string, string, error) {
	if s.IsHost() {
		return shell, cwd, nil
	}
	if shell != "" && shell != s.Shell {
		return "", "", fmt.Errorf("session shell %q is fixed by the target's --sandbox-shell %q", shell, s.Shell)
	}
	if cwd == "" {
		return s.Shell, s.Workdir, nil
	}
	if !Within(s.Workdir, cwd) {
		return "", "", fmt.Errorf("session cwd %q is outside the sandbox workdir %q", cwd, s.Workdir)
	}
	return s.Shell, cwd, nil
}

// Within reports whether p is root or below it after lexical cleaning. The
// container bind-mounts root, so a path outside it does not exist there.
func Within(root, p string) bool {
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	if p == root {
		return true
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Command builds the process for one session shell. env is the complete
// environment for a host shell; for a container it is the small allowlist the
// live agent passes as -e, never the daemon's environment.
func (s Spec) Command(shell, cwd string, env []string, uid, gid int) (*exec.Cmd, error) {
	if s.IsHost() {
		cmd := exec.Command(shell)
		if cwd != "" {
			cmd.Dir = cwd
		}
		cmd.Env = env
		return cmd, nil
	}
	if s.Backend != "docker" && s.Backend != "podman" {
		return nil, fmt.Errorf("sandbox backend %q cannot build a command", s.Backend)
	}
	args := []string{
		"run", "--rm", "-i",
		"--pull=never",
		"--network", s.Network,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
	}
	if s.Memory != "" {
		args = append(args, "--memory", s.Memory)
	}
	if s.CPUs != "" {
		args = append(args, "--cpus", s.CPUs)
	}
	if s.Pids > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", s.Pids))
	}
	args = append(args, "-v", s.Workdir+":"+s.Workdir+":rw")
	workdir := s.Workdir
	if cwd != "" {
		workdir = cwd
	}
	args = append(args, "-w", workdir)
	if s.Backend == "podman" {
		args = append(args, "--userns=keep-id")
	} else {
		args = append(args, "--user", fmt.Sprintf("%d:%d", uid, gid))
	}
	args = append(args, "-e", "HOME=/tmp")
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	args = append(args, "--entrypoint", s.Shell, s.Image)
	return exec.Command(s.Backend, args...), nil
}

// Describe is the one-line summary doctor prints.
func (s Spec) Describe() string {
	if s.IsHost() {
		return "host"
	}
	parts := []string{s.Backend, "image=" + s.Image, "workdir=" + s.Workdir, "network=" + s.Network}
	if s.Memory != "" {
		parts = append(parts, "memory="+s.Memory)
	}
	if s.CPUs != "" {
		parts = append(parts, "cpus="+s.CPUs)
	}
	if s.Pids > 0 {
		parts = append(parts, fmt.Sprintf("pids=%d", s.Pids))
	}
	return strings.Join(parts, " ")
}
