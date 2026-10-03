// Package update provides a non-blocking version check against GitHub Releases.
package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const checkTimeout = 5 * time.Second

// releaseTagRE matches the only tags a release may come from: vX.Y.Z (the
// release workflow refuses any other tag). Only the maintainer can create v*
// tags (repository ruleset); collaborators can still publish releases on
// other tags, so anything else is ignored rather than offered as an update.
var releaseTagRE = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// CheckResult is the outcome of a version check.
type CheckResult struct {
	UpdateAvailable bool
	LatestVersion   string
	DownloadURL     string
	CurrentVersion  string
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Author  struct {
		Login string `json:"login"`
	} `json:"author"`
}

// releaseAuthor is the account the release workflow publishes as. Collaborators
// can create a release on an existing v* tag by hand before the workflow does;
// only workflow-published releases are offered as updates.
const releaseAuthor = "github-actions[bot]"

// Check queries the GitHub Releases API for the latest release and compares
// it with the current version. Returns immediately with UpdateAvailable=false
// if anything fails (network, parse, invalid version). Never panics.
func Check(owner, repo, currentVersion string) CheckResult {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	return checkInternal(url, currentVersion, checkTimeout)
}

// checkInternal is the testable core of Check with injectable URL and timeout.
func checkInternal(url, currentVersion string, timeout time.Duration) CheckResult {
	result := CheckResult{CurrentVersion: currentVersion}

	client := &http.Client{Timeout: timeout, CheckRedirect: core.SafeRedirect}

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

	if !releaseTagRE.MatchString(release.TagName) || release.Author.Login != releaseAuthor {
		return result
	}

	result.LatestVersion = release.TagName
	result.DownloadURL = release.HTMLURL

	if isNewer(release.TagName, currentVersion) {
		result.UpdateAvailable = true
	}

	return result
}

// isNewer returns true if latest is a higher semver than current.
// Strips leading "v" from both. Returns false on any parse error.
func isNewer(latest, current string) bool {
	latestParts, ok1 := parseSemver(latest)
	currentParts, ok2 := parseSemver(current)
	if !ok1 || !ok2 {
		return false
	}

	for i := 0; i < 3; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return false
}

// parseSemver parses "v1.2.3" or "1.2.3" into [3]int{1, 2, 3}.
func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	// Release tags are two-component (v1.3) or three-component (v1.3.1);
	// a missing patch component counts as 0.
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [3]int{}, false
	}
	var result [3]int
	for i, p := range parts {
		// Strip any pre-release suffix (e.g., "3-rc1")
		if idx := strings.IndexAny(p, "-+"); idx >= 0 {
			p = p[:idx]
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		result[i] = n
	}
	return result, true
}
