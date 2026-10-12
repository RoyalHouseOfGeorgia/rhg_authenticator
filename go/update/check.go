package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const checkTimeout = 5 * time.Second

// releaseTagRE matches the only tags a release may come from: vX.Y.Z (the
// release workflow refuses any other tag). Only the maintainer can create v*
// tags (repository ruleset); collaborators can still publish releases on
// other tags, so anything else is ignored rather than offered as an update.
var releaseTagRE = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// darwinAssetName is the exact release asset name the in-app macOS updater
// downloads. Any other asset (or none) means the update must be done manually.
const darwinAssetName = "rhg-authenticator-darwin-arm64.zip"

// CheckResult is the outcome of a version check.
type CheckResult struct {
	UpdateAvailable bool
	LatestVersion   string
	// DownloadURL is the release page (html_url), for manual updates.
	DownloadURL    string
	CurrentVersion string
	// AssetURL is the https browser_download_url of the darwinAssetName asset,
	// or empty if the release has no such asset or its URL is not https.
	// Empty means the caller must fall back to the manual update path.
	AssetURL string
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Uploader           struct {
		Login string `json:"login"`
	} `json:"uploader"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Author  struct {
		Login string `json:"login"`
	} `json:"author"`
	Assets []githubAsset `json:"assets"`
}

// releaseAuthor is the account the release workflow publishes as. Collaborators
// can create a release on an existing v* tag by hand before the workflow does;
// only workflow-published releases are offered as updates.
const releaseAuthor = "github-actions[bot]"

// Check queries the GitHub Releases API for the latest release and compares
// it with the current version. Returns immediately with UpdateAvailable=false
// if anything fails (network, parse, invalid version). Never panics.
func Check(owner, repo, currentVersion string) CheckResult {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	return checkInternal(apiURL, currentVersion, checkTimeout)
}

// checkInternal is the testable core of Check with injectable URL and timeout.
func checkInternal(apiURL, currentVersion string, timeout time.Duration) CheckResult {
	result := CheckResult{CurrentVersion: currentVersion}

	client := &http.Client{Timeout: timeout, CheckRedirect: core.SafeRedirect}

	resp, err := client.Get(apiURL)
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
	result.AssetURL = darwinAssetURL(release.Assets)

	if isNewer(release.TagName, currentVersion) {
		result.UpdateAvailable = true
	}

	return result
}

// darwinAssetURL returns the browser_download_url of the asset named exactly
// darwinAssetName, provided it parses as an absolute https URL with a host.
// Returns "" otherwise. The first asset with the exact name wins; GitHub
// rejects duplicate asset names within one release.
func darwinAssetURL(assets []githubAsset) string {
	for _, a := range assets {
		if a.Name != darwinAssetName {
			continue
		}
		// A filter, not the security control: it drops assets a collaborator
		// uploaded by hand, but a workflow on an unprotected branch can still
		// upload as the bot. What actually stops a bad bundle is the pinned
		// code-signing requirement plus the sealed version == tag (stage).
		if a.Uploader.Login != releaseAuthor {
			return ""
		}
		if !isHTTPSURL(a.BrowserDownloadURL) {
			return ""
		}
		return a.BrowserDownloadURL
	}
	return ""
}
