package buildinfo

import "testing"

func TestIsRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"dev default", "dev", false},
		{"semver release", "v1.0.0", true},
		{"release candidate", "v1.0.0-rc1", true},
		{"git describe fallback", "abc1234", false},
		{"starts with v but not digit", "vagrant", false},
		{"bare v too short", "v", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := Version
			t.Cleanup(func() { Version = orig })

			Version = tt.version

			if got := IsRelease(); got != tt.want {
				t.Errorf("IsRelease() = %v for %q, want %v", got, tt.version, tt.want)
			}
			if got := IsDebug(); got != !tt.want {
				t.Errorf("IsDebug() = %v for %q, want %v", got, tt.version, !tt.want)
			}
		})
	}
}
