package live

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tyd/internal/safefile"
)

const (
	metaFile = "meta.json"
	sockFile = "agent.sock"
	agentPID = "agent.pid"
	shellPID = "shell.pid"
	agentLog = "agent.log"
)

// Meta is persisted under ~/.tyd/live/<id>/meta.json.
type Meta struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	OwnerPub  string `json:"owner_pub"`
	PeerID    string `json:"peer_id,omitempty"`
	Shell     string `json:"shell"`
	Cwd       string `json:"cwd"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
	CreatedAt string `json:"created_at"`
	// OutputLogMax is the disk cap in bytes. Zero means the agent default.
	OutputLogMax int64 `json:"output_log_max,omitempty"`
}

func Dir(root, id string) string {
	return filepath.Join(root, id)
}

func MetaPath(dir string) string     { return filepath.Join(dir, metaFile) }
func SockPath(dir string) string     { return filepath.Join(dir, sockFile) }
func AgentPIDPath(dir string) string { return filepath.Join(dir, agentPID) }
func ShellPIDPath(dir string) string { return filepath.Join(dir, shellPID) }
func LogPath(dir string) string      { return filepath.Join(dir, agentLog) }

func SaveMeta(dir string, m Meta) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteFile(MetaPath(dir), append(b, '\n'), 0o600)
}

func LoadMeta(dir string) (Meta, error) {
	b, err := os.ReadFile(MetaPath(dir))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("meta: %w", err)
	}
	if m.ID == "" {
		return Meta{}, fmt.Errorf("meta missing id")
	}
	return m, nil
}

func WritePID(path string, pid int) error {
	return safefile.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

func ReadPID(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(s)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid %q", s)
	}
	return pid, nil
}

// ListDirs returns live session directories under root (non-recursive).
func ListDirs(root string) ([]string, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(MetaPath(dir)); err != nil {
			continue
		}
		out = append(out, dir)
	}
	return out, nil
}

func RemoveDir(dir string) {
	_ = os.RemoveAll(dir)
}
