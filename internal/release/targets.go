package release

// Platforms are the three release families: common Unix machines that have a TTY.
const (
	Linux   = "linux"
	Darwin  = "darwin"
	FreeBSD = "freebsd"
)

// Arches are the CPU architectures built for every platform.
const (
	AMD64 = "amd64"
	ARM64 = "arm64"
)

type Target struct {
	GOOS   string
	GOARCH string
}

func Platforms() []string {
	return []string{Linux, Darwin, FreeBSD}
}

func Arches() []string {
	return []string{AMD64, ARM64}
}

func Targets() []Target {
	var out []Target
	for _, os := range Platforms() {
		for _, arch := range Arches() {
			out = append(out, Target{GOOS: os, GOARCH: arch})
		}
	}
	return out
}

func ArchiveName(platform string) string {
	return "tyd-" + platform + ".tar.gz"
}

func BinaryName(arch string) string {
	return "tyd-" + arch
}
