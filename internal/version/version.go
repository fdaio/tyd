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

// parsedVersion is a semantic version with pre-release info preserved
// for ordering (a pre-release is older than the release itself).
type parsedVersion struct {
	major, minor, patch int
	pre                 string // "" for releases, e.g. "rc1" for v1.2.3-rc1
}

// Parse splits "v1.2.3" (or "1.2.3", "v1.2.3-rc1") into its parts.
func Parse(v string) (major, minor, patch int, err error) {
	pv, err := parseFull(v)
	if err != nil {
		return 0, 0, 0, err
	}
	return pv.major, pv.minor, pv.patch, nil
}

func parseFull(v string) (parsedVersion, error) {
	var pv parsedVersion
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "-"); i >= 0 {
		pv.pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return pv, fmt.Errorf("invalid version %q: want major.minor.patch", v)
	}
	var err error
	if pv.major, err = strconv.Atoi(parts[0]); err != nil {
		return pv, fmt.Errorf("invalid major in %q: %w", v, err)
	}
	if pv.minor, err = strconv.Atoi(parts[1]); err != nil {
		return pv, fmt.Errorf("invalid minor in %q: %w", v, err)
	}
	if pv.patch, err = strconv.Atoi(parts[2]); err != nil {
		return pv, fmt.Errorf("invalid patch in %q: %w", v, err)
	}
	return pv, nil
}

// Compare returns -1 if a < b, 0 if a == b, +1 if a > b.
// "dev" is always considered older than any release.
// A pre-release (v1.2.3-rc1) is older than the release (v1.2.3).
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
	pa, aerr := parseFull(a)
	pb, berr := parseFull(b)
	if aerr != nil || berr != nil {
		return 0
	}
	if pa.major != pb.major {
		return cmpInt(pa.major, pb.major)
	}
	if pa.minor != pb.minor {
		return cmpInt(pa.minor, pb.minor)
	}
	if pa.patch != pb.patch {
		return cmpInt(pa.patch, pb.patch)
	}
	// Same triple: a pre-release is older than the release.
	// Two pre-releases compare lexically (rc1 < rc2).
	switch {
	case pa.pre == pb.pre:
		return 0
	case pa.pre == "":
		return 1 // a is the release, b is pre-release
	case pb.pre == "":
		return -1 // b is the release, a is pre-release
	case pa.pre < pb.pre:
		return -1
	default:
		return 1
	}
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
