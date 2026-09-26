package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTargetsCoverThreeTTYPlatformsAndTwoArches(t *testing.T) {
	plats := Platforms()
	if len(plats) != 3 {
		t.Fatalf("got %d platforms, want 3 (linux/darwin/freebsd)", len(plats))
	}
	wantPlats := map[string]bool{Linux: false, Darwin: false, FreeBSD: false}
	for _, p := range plats {
		if _, ok := wantPlats[p]; !ok {
			t.Fatalf("unexpected platform %q", p)
		}
		wantPlats[p] = true
	}
	for p, seen := range wantPlats {
		if !seen {
			t.Fatalf("missing platform %q", p)
		}
	}

	arches := Arches()
	if len(arches) != 2 {
		t.Fatalf("got %d arches, want 2 (amd64/arm64)", len(arches))
	}

	targets := Targets()
	if len(targets) != 6 {
		t.Fatalf("got %d targets, want 6", len(targets))
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		key := tg.GOOS + "/" + tg.GOARCH
		if seen[key] {
			t.Fatalf("duplicate target %s", key)
		}
		seen[key] = true
		if ArchiveName(tg.GOOS) != "tyd-"+tg.GOOS+".tar.gz" {
			t.Fatalf("archive name %q", ArchiveName(tg.GOOS))
		}
		if BinaryName(tg.GOARCH) != "tyd-"+tg.GOARCH {
			t.Fatalf("binary name %q", BinaryName(tg.GOARCH))
		}
	}
}

func TestReleaseTargetsCrossCompile(t *testing.T) {
	root := moduleRoot(t)
	dest := t.TempDir()
	for _, tg := range Targets() {
		t.Run(tg.GOOS+"/"+tg.GOARCH, func(t *testing.T) {
			out := filepath.Join(dest, tg.GOOS+"-"+tg.GOARCH)
			cmd := exec.Command("go", "build", "-o", out, "./cmd/tyd")
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"CGO_ENABLED=0",
				"GOOS="+tg.GOOS,
				"GOARCH="+tg.GOARCH,
			)
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go build: %v\n%s", err, b)
			}
			st, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() == 0 {
				t.Fatal("empty binary")
			}
		})
	}
}

func TestMakefileListsReleasePlatforms(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, p := range Platforms() {
		if !strings.Contains(text, p) {
			t.Fatalf("Makefile missing platform %q", p)
		}
	}
	for _, a := range Arches() {
		if !strings.Contains(text, a) {
			t.Fatalf("Makefile missing arch %q", a)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
