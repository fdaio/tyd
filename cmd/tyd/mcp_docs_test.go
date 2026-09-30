package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The MCP flags are quoted in three places — `tyd mcp help`, `tyd --help` and
// docs/cli.md — and a model reads the schema rather than any of them. A flag
// that exists in the binary and not in the docs is a flag nobody can find, and a
// flag in the docs that the binary does not have is worse: it sends an operator
// looking for a switch that is not there.
func TestEveryMCPFlagIsDocumented(t *testing.T) {
	var help bytes.Buffer
	writeMCPHelp(&help, false)

	// A help row starts with the flag in braces; a reference row starts with it in
	// backticks. Both are the flag, so both are read here.
	helpFlag := regexp.MustCompile("(?m)^\\s+\\{?\"?(--[a-z-]+)")
	docFlag := regexp.MustCompile("(?m)^\\| `(--[a-z-]+)")

	seen := map[string]bool{}
	for _, m := range helpFlag.FindAllStringSubmatch(help.String(), -1) {
		seen[m[1]] = true
	}
	if len(seen) == 0 {
		t.Fatalf("no flags found in the mcp help:\n%s", help.String())
	}
	doc := readRepoFile(t, "../../docs/cli.md")
	for _, m := range docFlag.FindAllStringSubmatch(doc, -1) {
		delete(seen, m[1])
	}
	if len(seen) > 0 {
		var missing []string
		for f := range seen {
			missing = append(missing, f)
		}
		t.Fatalf("flags in `tyd mcp help` but not in docs/cli.md: %v", missing)
	}
}

// The check runs the other way as well, over the rows that talk about mcp: a
// documented flag the binary does not have is a promise the reference cannot
// keep, and it is the one an operator acts on.
func TestDocumentedMCPFlagsExist(t *testing.T) {
	var help bytes.Buffer
	writeMCPHelp(&help, false)
	var root bytes.Buffer
	writeRootHelp(&root, false)
	known := help.String() + root.String()

	doc := readRepoFile(t, "../../docs/cli.md")
	inlineFlag := regexp.MustCompile("`--[a-z-]+`")
	for _, line := range strings.Split(doc, "\n") {
		if !strings.Contains(line, "mcp") {
			continue
		}
		for _, m := range inlineFlag.FindAllString(line, -1) {
			flag := strings.Trim(m, "`")
			if !strings.Contains(known, flag) {
				t.Errorf("docs/cli.md documents %s, but no help output has it: %q", flag, line)
			}
		}
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return string(b)
}
