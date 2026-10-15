package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Check state lives under ~/.tyd, next to the daemon state.
const (
	checkCacheFile = "update-check.json"
	checkInterval  = 24 * time.Hour
	githubAPI      = "https://api.github.com/repos/fdaio/tyd/releases/latest"
)

// checkCache records the last update check so we don't hit the API
// on every invocation.
type checkCache struct {
	CheckedAt time.Time `json:"checked_at"`
	LatestTag string    `json:"latest_tag"`
}

// CheckForUpdate returns release info if a newer version exists.
// It caches the result for 24h; failures are silent (nil, nil) so a
// broken network never blocks tyd. Set TYD_NO_UPDATE_CHECK=1 to skip.
func CheckForUpdate() *Info {
	return checkForUpdate(false)
}

// LatestRelease returns the latest release info regardless of the
// current version. Used by `tyd upgrade`, which works even on dev
// builds (the user explicitly asked to upgrade).
func LatestRelease() *Info {
	return checkForUpdate(true)
}

func checkForUpdate(force bool) *Info {
	if os.Getenv("TYD_NO_UPDATE_CHECK") != "" {
		return nil
	}
	// Dev builds have no meaningful "latest" to compare against,
	// unless the user explicitly asked (tyd upgrade).
	if Version == "dev" && !force {
		return nil
	}
	cached := readCache()
	if cached != nil && time.Since(cached.CheckedAt) < checkInterval {
		if force || IsNewer(Version, cached.LatestTag) {
			return &Info{Tag: cached.LatestTag, URL: downloadURL(cached.LatestTag)}
		}
		return nil
	}
	info := fetchLatest()
	if info == nil {
		return nil
	}
	writeCache(info.Tag)
	if force || IsNewer(Version, info.Tag) {
		return info
	}
	return nil
}

// downloadURL builds the tarball URL for this platform, matching the
// naming in scripts/install.sh: tyd-<os>-<arch>.tar.gz.
func downloadURL(tag string) string {
	return fmt.Sprintf(
		"https://github.com/fdaio/tyd/releases/download/%s/tyd-%s-%s.tar.gz",
		tag, runtime.GOOS, runtime.GOARCH,
	)
}

// githubRelease is the subset of the GitHub release API we need.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

func fetchLatest() *Info {
	// Short timeout: this runs after every command. A slow network
	// should fail fast and silently, not delay the user's command.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(githubAPI)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil
	}
	if rel.TagName == "" {
		return nil
	}
	return &Info{Tag: rel.TagName, URL: downloadURL(rel.TagName)}
}

func cachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".tyd", checkCacheFile)
}

func readCache() *checkCache {
	p := cachePath()
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var c checkCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil
	}
	return &c
}

func writeCache(tag string) {
	p := cachePath()
	if p == "" {
		return
	}
	c := checkCache{CheckedAt: time.Now(), LatestTag: tag}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	// Best effort: a failed cache write just means we check again next time.
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, data, 0o644)
}
