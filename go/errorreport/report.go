// Package errorreport builds and submits auto-reported issue bodies
// to the project's GitHub repository.
package errorreport

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

const (
	repoOwner           = "RoyalHouseOfGeorgia"
	repoName            = "rhg_authenticator"
	maxTitleLen         = 256
	maxBrowserBodyBytes = 1500
	issueNewURL         = "https://github.com/" + repoOwner + "/" + repoName + "/issues/new"
)

// Package-level function variables for test injection.
var (
	restoreSessionFunc = ghapi.RestoreSession
	newClientFunc      = ghapi.NewClientWithUser
)

// BuildIssueTitle constructs the issue title. The result is truncated
// to maxTitleLen characters.
func BuildIssueTitle(errType, shortDesc string) string {
	t := fmt.Sprintf("[Auto] %s: %s", errType, shortDesc)
	if len(t) > maxTitleLen {
		t = truncateToValidUTF8(t, maxTitleLen)
	}
	return t
}

// BuildIssueBody constructs the markdown body for an auto-reported issue.
// It never includes the error log: issues are posted to the public tracker
// without a preview, so operators send the log deliberately via
// Help → Export Error Log….
func BuildIssueBody(version, errType, errMsg string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("**Version:** %s\n", version))
	b.WriteString(fmt.Sprintf("**OS:** %s/%s\n", runtime.GOOS, runtime.GOARCH))
	b.WriteString(fmt.Sprintf("**Error type:** %s\n", errType))
	b.WriteString(fmt.Sprintf("**Error:** %s\n", core.StripControlChars(errMsg)))

	b.WriteString("\n---\n*Auto-reported by RHG Authenticator*\n")
	return b.String()
}

// ReportIssue attempts to file a GitHub issue via the API. If the user
// is not logged in or offline, it returns a pre-filled browser URL instead.
func ReportIssue(ctx context.Context, kr ghapi.Keyring, configDir string, title, body string) (resultURL string, err error) {
	tok, username, loggedIn, offline, err := restoreSessionFunc(ctx, kr, configDir)
	if err != nil {
		return browserURL(title, body), nil
	}

	if loggedIn && !offline {
		client := newClientFunc(tok.AccessToken, username)
		result, createErr := client.CreateIssue(ctx, title, body, []string{"bug", "auto-reported"})
		if createErr != nil {
			// Fall through to browser URL on API failure.
			return browserURL(title, body), nil
		}
		return result.HTMLURL, nil
	}

	// Logged in but offline, or not logged in — use browser fallback.
	return browserURL(title, body), nil
}

// browserURL constructs a pre-filled GitHub new-issue URL. The body is
// truncated to maxBrowserBodyBytes before URL-encoding to avoid
// exceeding browser URL length limits.
func browserURL(title, body string) string {
	if len(body) > maxBrowserBodyBytes {
		body = truncateToValidUTF8(body, maxBrowserBodyBytes)
		body += "\n\nReport truncated \u2014 use Help \u2192 Export Error Log\u2026 and attach the file."
	}
	v := url.Values{
		"title":  {title},
		"body":   {body},
		"labels": {"bug,auto-reported"},
	}
	return issueNewURL + "?" + v.Encode()
}

// truncateToValidUTF8 truncates s to at most maxBytes bytes without
// splitting a multi-byte UTF-8 sequence. It walks backward from the
// cut point to find a valid rune boundary.
func truncateToValidUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk backward to avoid splitting a multi-byte rune.
	for maxBytes > 0 && !isUTF8Start(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// isUTF8Start reports whether b is an ASCII byte or a UTF-8 leading byte.
func isUTF8Start(b byte) bool {
	return b&0xC0 != 0x80 // not a continuation byte
}
