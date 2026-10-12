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

// TestIsNewer_MixedSpellings: plist ("1.5.0") and tag ("v1.5.0") spellings
// compare correctly against each other, including legacy two-part tags.
func TestIsNewer_MixedSpellings(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"v1.5.0", "1.4.0", true},
		{"1.5.0", "v1.4", true},
		{"v1.4", "1.4.0", false},
		{"1.4.0", "v1.4", false},
		{"v1.5.0", "1.5.0", false},
		{"1.5.1", "v1.5", true},
	}
	for _, tt := range tests {
		t.Run(tt.latest+"_vs_"+tt.current, func(t *testing.T) {
			if got := isNewer(tt.latest, tt.current); got != tt.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}
