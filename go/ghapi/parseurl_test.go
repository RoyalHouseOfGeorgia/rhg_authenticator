package ghapi

import "testing"

func TestGitHubURLOrEmpty(t *testing.T) {
	for raw, want := range map[string]string{
		"https://github.com/o/r/pull/1": "https://github.com/o/r/pull/1",
		"http://github.com/o/r":         "",
		"https://evil.example/o/r":      "",
		"https://u@github.com/o/r":      "",
		"":                              "",
	} {
		if got := GitHubURLOrEmpty(raw); got != want {
			t.Errorf("GitHubURLOrEmpty(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseGitHubURL_Valid(t *testing.T) {
	if ParseGitHubURL("https://github.com/owner/repo/commit/abc123") == nil {
		t.Error("expected non-nil for valid GitHub URL")
	}
}

func TestParseGitHubURL_HTTP(t *testing.T) {
	if ParseGitHubURL("http://github.com/owner/repo/commit/abc123") != nil {
		t.Error("expected nil for HTTP scheme")
	}
}

func TestParseGitHubURL_NonGitHub(t *testing.T) {
	if ParseGitHubURL("https://gitlab.com/owner/repo/commit/abc123") != nil {
		t.Error("expected nil for non-GitHub host")
	}
}

func TestParseGitHubURL_Malformed(t *testing.T) {
	if ParseGitHubURL("://not-a-url") != nil {
		t.Error("expected nil for malformed URL")
	}
}

func TestParseGitHubURL_EmptyString(t *testing.T) {
	if ParseGitHubURL("") != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseGitHubURL_WithCredentials(t *testing.T) {
	if ParseGitHubURL("https://user:pass@github.com/owner/repo") != nil {
		t.Error("expected nil for URL with embedded credentials")
	}
}
