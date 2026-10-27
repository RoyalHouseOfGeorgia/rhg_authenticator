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
		{"release page", "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.5.1", "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v1.5.1"},
		{"github root", "https://github.com/", "https://github.com/"},
		{"lookalike host", "https://github.com.evil.example/x", ""},
		{"subdomain", "https://api.github.com/x", ""},
		{"explicit port", "https://github.com:443/x", ""},
		{"javascript", "javascript:alert(1)", ""},
		{"malformed escape", "https://github.com/%zz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GitHubURLOrEmpty(tt.raw); got != tt.want {
				t.Errorf("GitHubURLOrEmpty(%q) = %q, want %q", tt.raw, got, tt.want)
			}
			u := ParseGitHubURL(tt.raw)
			if accepted := u != nil; accepted != (tt.want != "") {
				t.Errorf("ParseGitHubURL(%q) accepted = %v, want %v", tt.raw, accepted, tt.want != "")
			}
			if u != nil && u.String() != tt.raw {
				t.Errorf("ParseGitHubURL(%q).String() = %q, want the input unchanged", tt.raw, u.String())
			}
		})
	}
}
