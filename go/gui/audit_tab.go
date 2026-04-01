package gui

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

const (
	commitsPerPage    = 50
	maxCommitMsgRunes = 80
)

// formatCommitSummary returns a one-line summary for the audit list.
func formatCommitSummary(c ghapi.RegistryCommit) string {
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
	if maxLen <= 0 {
		return ""
	}
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
func NewAuditTab(window fyne.Window, lastUpdateCh chan<- string) *fyne.Container {
	var commits []ghapi.RegistryCommit
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
	sent := false

	doFetch := func() {
		if !fetching.CompareAndSwap(false, true) {
			return
		}
		refreshBtn.Disable()
		statusLabel.SetText("Fetching...")
		currentETag := lastETag // capture under UI thread
		go func() {
			result, newETag, err := ghapi.FetchRegistryCommits("", commitsPerPage, currentETag)
			fyne.Do(func() {
				fetching.Store(false)
				refreshBtn.Enable()
				if err != nil {
					if ghapi.IsRateLimited(err) {
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
					if !sent && len(commits) > 0 {
						select {
						case lastUpdateCh <- commits[0].Commit.Author.Date:
						default: // channel full, skip
						}
						sent = true
					}
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
