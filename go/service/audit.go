package service

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

const (
	commitsPerPage    = 50
	maxCommitMsgRunes = 80
)

// auditState is the last registry commit fetch, held under App.mu.
type auditState struct {
	rows []AuditRow
	etag string
}

// AuditRow is one registry commit in the audit list.
type AuditRow struct {
	Summary string `json:"summary"`
	URL     string `json:"url"` // the commit page; "" unless an https github.com URL
}

// AuditResult is the registry commit history and the status line to show.
type AuditResult struct {
	Rows   []AuditRow `json:"rows"`
	Status string     `json:"status"`
}

// AuditCommits fetches the registry file's recent commits. When nothing
// changed since the last fetch it returns the previous rows. It returns ErrBusy
// while another fetch runs; other errors keep the previous rows, are logged,
// and their text is user-facing.
func (a *App) AuditCommits() (AuditResult, error) {
	if !a.auditing.CompareAndSwap(false, true) {
		return AuditResult{}, ErrBusy
	}
	defer a.auditing.Store(false)

	a.mu.Lock()
	etag := a.audit.etag
	a.mu.Unlock()
	commits, newETag, err := a.fetchCommits("", commitsPerPage, etag)
	if err != nil {
		a.logger.Logf("audit: registry commit fetch failed: %s", core.SanitizeForLog(err.Error()))
		if ghapi.IsRateLimited(err) {
			return AuditResult{}, userErr(ghapi.UserMessage(err), err)
		}
		return AuditResult{}, userErr("Failed to fetch registry history.", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if commits == nil { // 304 Not Modified
		return AuditResult{Rows: append([]AuditRow(nil), a.audit.rows...), Status: "No changes since last check"}, nil
	}
	rows := make([]AuditRow, len(commits))
	for i, c := range commits {
		rows[i] = AuditRow{Summary: formatCommitSummary(c), URL: ghapi.GitHubURLOrEmpty(c.HTMLURL)}
	}
	a.audit.rows, a.audit.etag = rows, newETag
	return AuditResult{Rows: append([]AuditRow(nil), rows...), Status: fmt.Sprintf("Loaded %d commits", len(rows))}, nil
}

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
