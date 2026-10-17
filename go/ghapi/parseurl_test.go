package ghapi

import "testing"

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
