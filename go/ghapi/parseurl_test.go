package ghapi

import "testing"

// Each row also checks ParseGitHubURL directly, so its rejections stay
// covered if GitHubURLOrEmpty stops delegating to it.
func TestGitHubURLOrEmpty(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"https pull", "https://github.com/o/r/pull/1", "https://github.com/o/r/pull/1"},
		{"http", "http://github.com/o/r", ""},
		{"other host", "https://evil.example/o/r", ""},
		{"user info", "https://u@github.com/o/r", ""},
		{"ParseGitHubURL_Valid", "https://github.com/owner/repo/commit/abc123", "https://github.com/owner/repo/commit/abc123"},
		{"ParseGitHubURL_HTTP", "http://github.com/owner/repo/commit/abc123", ""},
		{"ParseGitHubURL_NonGitHub", "https://gitlab.com/owner/repo/commit/abc123", ""},
		{"ParseGitHubURL_Malformed", "://not-a-url", ""},
		{"ParseGitHubURL_EmptyString", "", ""},
		{"ParseGitHubURL_WithCredentials", "https://user:pass@github.com/owner/repo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubURLOrEmpty(tt.raw); got != tt.want {
				t.Errorf("GitHubURLOrEmpty(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			if accepted := ParseGitHubURL(tt.raw) != nil; accepted != (tt.want != "") {
				t.Errorf("ParseGitHubURL(%q) accepted = %v, want %v", tt.raw, accepted, tt.want != "")
			}
		})
	}
}
