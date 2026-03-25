package ghapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RegistryCommit represents a single commit from the GitHub Commits API.
type RegistryCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

const (
	commitFetchTimeout = 10 * time.Second
	maxCommitsBytes    = 1 << 20 // 1 MiB
)

// safeRedirect rejects non-HTTPS redirects and enforces a 10-redirect limit.
func safeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-HTTPS URL rejected")
	}
	return nil
}

// commitClient is reused across FetchRegistryCommits calls for connection pooling.
var commitClient = &http.Client{Timeout: commitFetchTimeout, CheckRedirect: safeRedirect}

// FetchRegistryCommits retrieves registry file commits from the GitHub API.
// If etag is non-empty, it is sent as If-None-Match for conditional requests.
// On 304 Not Modified, returns (nil, etag, nil) — nil commits signals no change.
func FetchRegistryCommits(perPage int, etag string) ([]RegistryCommit, string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s&per_page=%d",
		DefaultOwner, DefaultRepo, RegistryFilePath, perPage)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := commitClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, "", &APIError{StatusCode: http.StatusTooManyRequests, Message: "rate limited"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return nil, "", fmt.Errorf("unexpected Content-Type: %s", ct)
	}

	newETag := resp.Header.Get("ETag")

	var commits []RegistryCommit
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCommitsBytes)).Decode(&commits); err != nil {
		return nil, "", fmt.Errorf("JSON decode: %w", err)
	}

	return commits, newETag, nil
}
