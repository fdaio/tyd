// Package version handles tyd's version identity, comparison, and
// update checking.
//
// The version is injected at build time via ldflags:
//
//	go build -ldflags "-X tyd/internal/version.Version=v1.2.3" ./cmd/tyd
//
// Release builds set it; dev builds report "dev".
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is the current build's version. Set via ldflags at release time.
var Version = "dev"

// Info describes a released version available for upgrade.
type Info struct {
	// Tag is the release tag, e.g. "v1.2.3".
	Tag string
	// URL is the download URL for this platform's tarball.
	URL string
	// SHA256 is the expected hex checksum of the tarball, if known.
	SHA256 string
}

// Parse splits "v1.2.3" (or "1.2.3") into major, minor, patch.
// Pre-release suffixes (e.g. "-rc1") are stripped.
func Parse(v string) (major, minor, patch int, err error) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "-"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid version %q: want major.minor.patch", v)
	}
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, 0, fmt.Errorf("invalid major in %q: %w", v, err)
	}
	if minor, err = strconv.Atoi(parts[1]); err != nil {
		return 0, 0, 0, fmt.Errorf("invalid minor in %q: %w", v, err)
	}
	if patch, err = strconv.Atoi(parts[2]); err != nil {
		return 0, 0, 0, fmt.Errorf("invalid patch in %q: %w", v, err)
	}
	return major, minor, patch, nil
}

// Compare returns -1 if a < b, 0 if a == b, +1 if a > b.
// "dev" is always considered older than any release.
// Invalid versions sort as equal (0) rather than erroring, so a
// malformed tag never blocks the update check.
func Compare(a, b string) int {
	if a == b {
		return 0
	}
	if a == "dev" {
		return -1
	}
	if b == "dev" {
		return 1
	}
	amaj, amin, apat, aerr := Parse(a)
	bmaj, bmin, bpat, berr := Parse(b)
	if aerr != nil || berr != nil {
		return 0
	}
	if amaj != bmaj {
		return cmpInt(amaj, bmaj)
	}
	if amin != bmin {
		return cmpInt(amin, bmin)
	}
	return cmpInt(apat, bpat)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// IsNewer reports whether the candidate release is newer than current.
func IsNewer(current, candidate string) bool {
	return Compare(current, candidate) < 0
}
