package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in          string
		major       int
		minor       int
		patch       int
		expectError bool
	}{
		{"v1.2.3", 1, 2, 3, false},
		{"1.2.3", 1, 2, 3, false},
		{"v0.0.1", 0, 0, 1, false},
		{"v10.20.30", 10, 20, 30, false},
		{"v1.2.3-rc1", 1, 2, 3, false},
		{"1.2", 0, 0, 0, true},
		{"v1.2.3.4", 0, 0, 0, true},
		{"abc", 0, 0, 0, true},
		{"", 0, 0, 0, true},
	}
	for _, tc := range tests {
		maj, min, pat, err := Parse(tc.in)
		if tc.expectError {
			if err == nil {
				t.Errorf("Parse(%q): expected error, got none", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if maj != tc.major || min != tc.minor || pat != tc.patch {
			t.Errorf("Parse(%q) = %d.%d.%d, want %d.%d.%d",
				tc.in, maj, min, pat, tc.major, tc.minor, tc.patch)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.4", "v1.2.3", 1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.2.3-rc1", "v1.2.3", -1}, // pre-release older than release
		{"v1.2.3", "v1.2.3-rc1", 1},
		{"v1.2.3-rc1", "v1.2.3-rc2", -1},
		{"v1.2.3-rc1", "v1.2.3-rc1", 0},
		{"dev", "v1.0.0", -1},
		{"v1.0.0", "dev", 1},
		{"dev", "dev", 0},
		{"bogus", "also-bogus", 0}, // invalid sorts as equal
	}
	for _, tc := range tests {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("v1.0.0", "v1.0.1") {
		t.Error("v1.0.1 should be newer than v1.0.0")
	}
	if IsNewer("v1.0.1", "v1.0.0") {
		t.Error("v1.0.0 should not be newer than v1.0.1")
	}
	if IsNewer("v1.0.0", "v1.0.0") {
		t.Error("same version should not be newer")
	}
	if !IsNewer("dev", "v0.0.1") {
		t.Error("any release should be newer than dev")
	}
}
