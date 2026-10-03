package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// botRelease builds a release as the release workflow publishes it.
func botRelease(tag, htmlURL string) githubRelease {
	r := githubRelease{TagName: tag, HTMLURL: htmlURL}
	r.Author.Login = releaseAuthor
	return r
}

func TestCheck_UpdateAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(botRelease("v2.0.0", "https://github.com/example/releases/v2.0.0"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if !result.UpdateAvailable {
		t.Fatal("expected update available")
	}
	if result.LatestVersion != "v2.0.0" {
		t.Fatalf("expected v2.0.0, got %s", result.LatestVersion)
	}
	if result.DownloadURL == "" {
		t.Fatal("expected download URL")
	}
}

func TestCheck_SameVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(botRelease("v1.0.0", "https://example.com"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update for same version")
	}
}

func TestCheck_OlderVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(botRelease("v0.9.0", "https://example.com"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update when latest is older")
	}
}

func TestCheck_Server404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on 404")
	}
}

func TestCheck_ServerTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer server.Close()

	// Use a very short timeout to test timeout behavior
	result := checkInternal(server.URL, "v1.0.0", 100*time.Millisecond)
	if result.UpdateAvailable {
		t.Fatal("expected no update on timeout")
	}
}

func TestCheck_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on invalid JSON")
	}
}

func TestCheck_EmptyTagName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(botRelease("", "https://example.com"))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on empty tag")
	}
}

// TestCheck_OnlyVTagsOfferUpdates: only maintainer-only v* tags may produce an
// update banner; a release on any other tag (which a collaborator could
// create) is ignored entirely.
func TestCheck_OnlyVTagsOfferUpdates(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{"v9.9.0", true},
		{"v9.9.1", true},
		{"v9.9", false},
		{"9.9", false},
		{"9.9.0", false},
		{"V9.9", false},
		{"v9.9-rc1", false},
		{"v9.9.1.2", false},
		{"v9", false},
		{"release-v9.9", false},
		{"v9.9\n", false},
		{"v9.9.0\n", false},
		{"v9.9.0 ", false},
		{"v９.9.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(botRelease(tc.tag, "https://github.com/x/y/releases/tag/"+tc.tag))
			}))
			defer server.Close()

			result := checkInternal(server.URL, "v1.4", checkTimeout)
			if result.UpdateAvailable != tc.want {
				t.Errorf("tag %q: UpdateAvailable = %v, want %v", tc.tag, result.UpdateAvailable, tc.want)
			}
			if !tc.want && (result.LatestVersion != "" || result.DownloadURL != "") {
				t.Errorf("tag %q: rejected release must not populate LatestVersion/DownloadURL", tc.tag)
			}
		})
	}
}

// TestCheck_OnlyWorkflowReleasesOfferUpdates: a release created by hand on a
// v* tag (e.g. by a collaborator before the workflow publishes) is ignored.
func TestCheck_OnlyWorkflowReleasesOfferUpdates(t *testing.T) {
	for _, author := range []string{"", "some-collaborator", "github-actions"} {
		t.Run(author, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rel := botRelease("v9.9.0", "https://github.com/x/y/releases/tag/v9.9.0")
				rel.Author.Login = author
				json.NewEncoder(w).Encode(rel)
			}))
			defer server.Close()

			result := checkInternal(server.URL, "v1.4", checkTimeout)
			if result.UpdateAvailable || result.DownloadURL != "" {
				t.Errorf("author %q: release must be ignored, got %+v", author, result)
			}
		})
	}
}

func TestCheck_ConnectionRefused(t *testing.T) {
	result := checkInternal("http://127.0.0.1:1", "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update on connection error")
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

func TestCheck_RejectsHTTPRedirect(t *testing.T) {
	// Server redirects to an HTTP URL — should be rejected by SafeRedirect.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.com/malicious", http.StatusFound)
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update when redirect to HTTP is rejected")
	}
}

func TestCheck_OversizedResponse(t *testing.T) {
	// Server returns a response body larger than 1MB.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write valid JSON prefix, then pad with spaces to exceed 1MB, then close the JSON.
		// The LimitReader should truncate the body, causing a JSON decode error.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://example.com/release","padding":"`))
		w.Write([]byte(strings.Repeat("A", 2<<20))) // 2MB of padding
		w.Write([]byte(`"}`))
	}))
	defer server.Close()

	result := checkInternal(server.URL, "v1.0.0", checkTimeout)
	if result.UpdateAvailable {
		t.Fatal("expected no update when response exceeds 1MB limit")
	}
}
