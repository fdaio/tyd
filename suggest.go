package main

import "strings"

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
		d := levenshtein(input, c)
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

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return len(b)
	}
	if b == "" {
		return len(a)
	}
	// Optimize when lengths differ a lot — still compute fully; inputs are tiny.
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = min(del, ins, sub)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
