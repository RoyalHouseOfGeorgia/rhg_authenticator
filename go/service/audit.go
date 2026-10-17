package service

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

const (
	CommitsPerPage    = 50
	maxCommitMsgRunes = 80
)

// FormatCommitSummary returns a one-line summary for the audit list.
func FormatCommitSummary(c ghapi.RegistryCommit) string {
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
