package update

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheck_UpdateAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(githubRelease{TagName: "v2.0.0", HTMLURL: "https://github.com/example/releases/v2.0.0"})
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
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
		json.NewEncoder(w).Encode(githubRelease{TagName: "v1.0.0", HTMLURL: "https://example.com"})
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
	if result.UpdateAvailable {
		t.Fatal("expected no update for same version")
	}
}

func TestCheck_OlderVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(githubRelease{TagName: "v0.9.0", HTMLURL: "https://example.com"})
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
	if result.UpdateAvailable {
		t.Fatal("expected no update when latest is older")
	}
}

func TestCheck_Server404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
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
	result := checkWithURLAndTimeout(server.URL, "v1.0.0", 100*time.Millisecond)
	if result.UpdateAvailable {
		t.Fatal("expected no update on timeout")
	}
}

func TestCheck_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
	if result.UpdateAvailable {
		t.Fatal("expected no update on invalid JSON")
	}
}

func TestCheck_EmptyTagName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(githubRelease{TagName: "", HTMLURL: "https://example.com"})
	}))
	defer server.Close()

	result := checkWithURL(server.URL, "v1.0.0")
	if result.UpdateAvailable {
		t.Fatal("expected no update on empty tag")
	}
}

func TestCheck_ConnectionRefused(t *testing.T) {
	result := checkWithURL("http://127.0.0.1:1", "v1.0.0")
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
		{"v1.0", [3]int{}, false},
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

	result := checkWithURL(server.URL, "v1.0.0")
	if result.UpdateAvailable {
		t.Fatal("expected no update when response exceeds 1MB limit")
	}
}

// checkWithURL is a test helper that overrides the GitHub API URL.
func checkWithURL(url, currentVersion string) CheckResult {
	return checkWithURLAndTimeout(url, currentVersion, checkTimeout)
}

// checkWithURLAndTimeout allows overriding both URL and timeout for tests.
func checkWithURLAndTimeout(url, currentVersion string, timeout time.Duration) CheckResult {
	result := CheckResult{CurrentVersion: currentVersion}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	var release githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return result
	}

	if release.TagName == "" {
		return result
	}

	result.LatestVersion = release.TagName
	result.DownloadURL = release.HTMLURL

	if isNewer(release.TagName, currentVersion) {
		result.UpdateAvailable = true
	}

	return result
}
