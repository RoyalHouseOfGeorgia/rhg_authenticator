package update

import "testing"

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"v1.5.0", "1.5.0", true},
		{"1.5.0", "1.5.0", true},
		{"v1.4", "1.4.0", true},
		{"1.4", "1.4.0", true},
		{"v10.20.30", "10.20.30", true},
		{"v1.5.0-rc1", "1.5.0", true},
		{"", "", false},
		{"dev", "", false},
		{"garbage", "", false},
		{"v1", "", false},
		{"../1.2.3", "", false},
		{"1.2.3/x", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := normalizeVersion(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("normalizeVersion(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSameVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.5.0", "1.5.0", true},
		{"1.5.0", "v1.5.0", true},
		{"v1.4", "1.4.0", true},
		{"1.4.0", "v1.4", true},
		{"v1.5", "v1.5.0", true},
		{"v1.5.0", "v1.5.1", false},
		{"v1.5.1", "1.5.0", false},
		{"v2.0.0", "1.0.0", false},
		{"", "", false},
		{"", "v1.0.0", false},
		{"v1.0.0", "", false},
		{"garbage", "garbage", false},
		{"garbage", "v1.0.0", false},
		{"dev", "dev", false},
		{"v1.0.0", "dev", false},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			if got := sameVersion(tt.a, tt.b); got != tt.want {
				t.Errorf("sameVersion(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"v1.2.3", "v1.2.2", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.10.0", "v1.9.0", true},
		{"v1.0.1", "v1.0.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.0.1", false},
		{"v0.9.0", "v1.0.0", false},
		{"1.2.3", "1.2.2", true},
		{"invalid", "v1.0.0", false},
		{"v1.0.0", "invalid", false},
		{"v1.0", "v1.0.0", false},
		{"v1.0.0-rc1", "v1.0.0", false},
		{"v1.3.1", "v1.3", true},
		{"v1.4", "v1.3", true},
		{"v1.4", "v1.3.1", true},
		{"v1.3", "v1.3", false},
		{"v1.3", "v1.3.1", false},
		// Plist ("1.5.0") and tag ("v1.5.0") spellings compare correctly
		// against each other, including legacy two-part tags.
		{"v1.5.0", "1.4.0", true},
		{"1.5.0", "v1.4", true},
		{"v1.4", "1.4.0", false},
		{"1.4.0", "v1.4", false},
		{"v1.5.0", "1.5.0", false},
		{"1.5.1", "v1.5", true},
	}

	for _, tt := range tests {
		t.Run(tt.latest+"_vs_"+tt.current, func(t *testing.T) {
			got := isNewer(tt.latest, tt.current)
			if got != tt.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
		ok    bool
	}{
		{"v1.2.3", [3]int{1, 2, 3}, true},
		{"1.2.3", [3]int{1, 2, 3}, true},
		{"v0.0.0", [3]int{0, 0, 0}, true},
		{"v1.0.0-rc1", [3]int{1, 0, 0}, true},
		{"invalid", [3]int{}, false},
		{"v1.0", [3]int{1, 0, 0}, true},
		{"v1.3-rc1", [3]int{1, 3, 0}, true},
		{"v1", [3]int{}, false},
		{"v1.2.3.4", [3]int{}, false},
		{"v1.0.abc", [3]int{}, false},
		{"", [3]int{}, false},
		{"v-1.0.0", [3]int{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := parseSemver(tt.input)
			if ok != tt.ok {
				t.Errorf("parseSemver(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("parseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
