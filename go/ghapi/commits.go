package ghapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
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

// commitClient is reused across FetchRegistryCommits calls for connection pooling.
var commitClient = &http.Client{Timeout: commitFetchTimeout, CheckRedirect: core.SafeRedirect}

// FetchRegistryCommits retrieves registry file commits from the GitHub API.
// baseURL overrides the default API base URL (pass "" for production).
// If etag is non-empty, it is sent as If-None-Match for conditional requests.
// On 304 Not Modified, returns (nil, etag, nil) — nil commits signals no change.
func FetchRegistryCommits(baseURL string, perPage int, etag string) ([]RegistryCommit, string, error) {
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}
	apiURL := fmt.Sprintf("%s/repos/%s/%s/commits?path=%s&per_page=%d",
		baseURL, DefaultOwner, DefaultRepo, RegistryFilePath, perPage)

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
		return nil, "", fmt.Errorf("unexpected Content-Type: %s", core.SanitizeForLog(ct))
	}

	newETag := resp.Header.Get("ETag")

	var commits []RegistryCommit
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCommitsBytes)).Decode(&commits); err != nil {
		return nil, "", fmt.Errorf("JSON decode: %w", err)
	}

	return commits, newETag, nil
}
