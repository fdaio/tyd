package strutil

import "testing"

func TestLevenshtein(t *testing.T) {
	if d := Levenshtein("wacth", "watch"); d != 2 {
		t.Fatalf("dist=%d", d)
	}
	if d := Levenshtein("watch", "watch"); d != 0 {
		t.Fatalf("dist=%d", d)
	}
}
