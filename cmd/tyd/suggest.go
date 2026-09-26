package main

import (
	"strings"

	"tyd/internal/strutil"
)

// suggestCommand returns the closest candidate for a typo'd command name.
// Empty string means no confident suggestion.
func suggestCommand(input string, candidates []string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" || len(candidates) == 0 {
		return ""
	}
	best := ""
	bestDist := -1
	for _, c := range candidates {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || c == input {
			continue
		}
		d := strutil.Levenshtein(input, c)
		if bestDist < 0 || d < bestDist || (d == bestDist && c < best) {
			bestDist = d
			best = c
		}
	}
	if bestDist < 0 || bestDist > maxSuggestDistance(input, best) {
		return ""
	}
	return best
}

func maxSuggestDistance(input, candidate string) int {
	n := len(input)
	if len(candidate) > n {
		n = len(candidate)
	}
	// Short commands: allow 1–2 edits (lsit→list, wacth→watch). Longer: ~1/3 of length.
	if n <= 8 {
		return 2
	}
	return (n + 2) / 3
}
