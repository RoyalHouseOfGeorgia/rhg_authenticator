package gui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
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
	githubOwner        = "royalhouseofgeorgia"
	githubRepo         = "rhg-authenticator"
	registryFilePath   = "keys/registry.json"
	commitsPerPage     = 50
	commitFetchTimeout = 10 * time.Second
	maxCommitsBytes    = 1 << 20 // 1 MiB
	maxCommitMsgRunes  = 80
)

// commitClient is reused across fetchCommits calls for connection pooling.
var commitClient = &http.Client{Timeout: commitFetchTimeout}

// fetchCommits retrieves registry file commits from the given GitHub API URL.
// If etag is non-empty, it is sent as If-None-Match for conditional requests.
// On 304 Not Modified, returns (nil, etag, nil) — nil commits signals no change.
func fetchCommits(apiURL string, etag string) ([]RegistryCommit, string, error) {

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
		return nil, "", fmt.Errorf("rate limited")
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

// formatCommitSummary returns a one-line summary for the audit list.
func formatCommitSummary(c RegistryCommit) string {
	// Date: parse RFC3339, fall back to raw string.
	dateStr := strings.TrimSpace(c.Commit.Author.Date)
	if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
		dateStr = t.Format("2006-Jan-02")
	}

	// Author: fall back to "Unknown".
	author := strings.TrimSpace(c.Commit.Author.Name)
	if author == "" {
		author = "Unknown"
	}

	// Message: first line only, truncated.
	msg := strings.TrimSpace(c.Commit.Message)
	if msg == "" {
		msg = "(no message)"
	} else {
		msg = strings.SplitN(msg, "\n", 2)[0]
	}
	msg = truncateRunes(msg, maxCommitMsgRunes)

	return fmt.Sprintf("%s  %s — %s", dateStr, author, msg)
}

// truncateRunes truncates s to maxLen runes, appending "..." if truncated.
func truncateRunes(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxLen]) + "..."
}

// parseGitHubURL validates and parses a URL as HTTPS github.com without
// embedded credentials. Returns nil if invalid.
func parseGitHubURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	if u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return nil
	}
	return u
}

// NewAuditTab creates the registry audit tab UI showing GitHub commit history.
func NewAuditTab(window fyne.Window) *fyne.Container {
	var commits []RegistryCommit
	statusLabel := widget.NewLabel("")

	list := widget.NewList(
		func() int {
			return len(commits)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			label, ok := obj.(*widget.Label)
			if !ok {
				return
			}
			if id < 0 || id >= len(commits) {
				return
			}
			label.SetText(formatCommitSummary(commits[id]))
		},
	)

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(commits) {
			return
		}
		if parsed := parseGitHubURL(commits[id].HTMLURL); parsed != nil {
			fyne.CurrentApp().OpenURL(parsed)
		}
		list.UnselectAll()
	}

	var fetching atomic.Bool
	var lastETag string
	var refreshBtn *widget.Button

	doFetch := func() {
		if !fetching.CompareAndSwap(false, true) {
			return
		}
		refreshBtn.Disable()
		statusLabel.SetText("Fetching...")
		currentETag := lastETag // capture under UI thread
		go func() {
			apiURL := fmt.Sprintf(
				"https://api.github.com/repos/%s/%s/commits?path=%s&per_page=%d",
				githubOwner, githubRepo, registryFilePath, commitsPerPage,
			)
			result, newETag, err := fetchCommits(apiURL, currentETag)
			fyne.Do(func() {
				fetching.Store(false)
				refreshBtn.Enable()
				if err != nil {
					if strings.Contains(err.Error(), "rate limited") {
						statusLabel.SetText("GitHub API rate limit reached — try again later")
					} else {
						statusLabel.SetText("Failed to fetch registry history")
					}
					return
				}
				if result != nil { // nil means 304, keep existing commits
					commits = result
					lastETag = newETag
					list.Refresh()
					statusLabel.SetText(fmt.Sprintf("Loaded %d commits", len(commits)))
				} else {
					statusLabel.SetText("No changes since last check")
				}
			})
		}()
	}

	refreshBtn = widget.NewButton("Refresh", doFetch)
	doFetch() // auto-fetch on creation

	topBar := container.NewBorder(nil, nil, nil, refreshBtn, statusLabel)
	return container.NewBorder(topBar, nil, nil, nil, list)
}
