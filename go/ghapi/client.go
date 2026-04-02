package ghapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const (
	DefaultOwner     = "RoyalHouseOfGeorgia"
	DefaultRepo      = "rhg_authenticator"
	RegistryFilePath = "verify/keys/registry.json"
	revocationPath   = "verify/keys/revocations.json"
	defaultAPIBaseURL = "https://api.github.com"
	maxResponseBytes = 2 * 1024 * 1024 // 2 MiB
	clientTimeout    = 30 * time.Second
	maxBranchRetries = 3
)

var (
	forkPollInterval    = 3 * time.Second
	forkMaxPollAttempts = 15
)

// APIError represents an error response from the GitHub API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API error (HTTP %d): %s", e.StatusCode, e.Message)
}

// IsUnauthorized reports whether err is a GitHub 401 Unauthorized error.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == 401
}

// IsForbidden reports whether err is a GitHub 403 Forbidden error.
func IsForbidden(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == 403
}

// IsRateLimited reports whether err is a GitHub 429 Rate Limited error.
func IsRateLimited(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == 429
}

// ForkError indicates a failure during the fork setup phase of PR creation.
type ForkError struct {
	Phase   string // "create", "poll", "sync"
	Wrapped error
}

func (e *ForkError) Error() string {
	return fmt.Sprintf("fork %s failed: %v", e.Phase, e.Wrapped)
}

func (e *ForkError) Unwrap() error { return e.Wrapped }

// IsForkError reports whether err is (or wraps) a *ForkError.
func IsForkError(err error) bool {
	var fe *ForkError
	return errors.As(err, &fe)
}

// Client is a GitHub API client scoped to a single repository.
type Client struct {
	token      string
	username   string
	HTTPClient *http.Client
	Owner      string
	Repo       string
	BaseURL    string // Override for testing; empty uses defaultAPIBaseURL.
}

// baseURL returns the effective API base URL for this client.
func (c *Client) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultAPIBaseURL
}

// String returns a redacted representation to prevent token leakage in logs.
func (c *Client) String() string {
	return fmt.Sprintf("Client{token:[REDACTED], Owner:%q, Repo:%q}", c.Owner, c.Repo)
}

// GoString returns a redacted representation for fmt %#v formatting.
func (c *Client) GoString() string {
	return c.String()
}

// PRResult holds the response from creating a pull request.
type PRResult struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// SafeRedirect is an alias for core.SafeRedirect, kept for in-package callers.
// For unauthenticated HTTP clients only.
var SafeRedirect = core.SafeRedirect

// safeCheckRedirect strips the Authorization header when a redirect targets
// a host outside *.github.com. For authenticated API clients only.
//
// Unauthenticated clients should use SafeRedirect instead, which rejects
// non-HTTPS redirects entirely.
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-HTTPS URL rejected")
	}
	origHost := via[0].URL.Host
	targetHost := req.URL.Host
	if targetHost != origHost && !IsGitHubHost(targetHost) {
		delete(req.Header, "Authorization")
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// IsGitHubHost reports whether host is "github.com" or a subdomain of it.
func IsGitHubHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port present
	}
	// Leading dot prevents suffix confusion (e.g., evil-github.com → false).
	return h == "github.com" || strings.HasSuffix(h, ".github.com")
}

// NewClient returns a Client configured with default owner/repo and a 30s timeout.
func NewClient(token string) *Client {
	return &Client{
		token: token,
		HTTPClient: &http.Client{
			Timeout:       clientTimeout,
			CheckRedirect: safeCheckRedirect,
		},
		Owner: DefaultOwner,
		Repo:  DefaultRepo,
	}
}

// NewClientWithUser returns a Client configured with default owner/repo, the caller's username, and a 30s timeout.
func NewClientWithUser(token, username string) *Client {
	c := NewClient(token)
	c.username = username
	return c
}

// doJSON performs an authenticated JSON API request.
// If body is non-nil it is marshaled to JSON. If result is non-nil, a
// successful (2xx) response body is unmarshaled into it.
func (c *Client) doJSON(ctx context.Context, method, urlPath string, body, result any) error {
	fullURL := c.baseURL() + urlPath

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	if len(respData) > maxResponseBytes {
		return fmt.Errorf("response body exceeded 2 MiB limit")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := extractErrorMessage(respData, resp.StatusCode)
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if result != nil && len(respData) > 0 {
		if err := json.Unmarshal(respData, result); err != nil {
			return fmt.Errorf("unmarshaling response: %w", err)
		}
	}
	return nil
}

// extractErrorMessage tries to pull a "message" field from a JSON error
// response. Falls back to a generic message for known status codes.
func extractErrorMessage(data []byte, statusCode int) string {
	var errBody struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &errBody) == nil && errBody.Message != "" {
		return core.SanitizeForLog(errBody.Message)
	}
	switch statusCode {
	case 429:
		return "rate limit exceeded"
	default:
		return http.StatusText(statusCode)
	}
}


// getRefFor returns the SHA of the given ref (e.g. "heads/main") for the specified owner/repo.
func (c *Client) getRefFor(ctx context.Context, owner, repo, ref string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/%s", owner, repo, ref)
	var resp struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	return resp.Object.SHA, nil
}

// getRef returns the SHA of the given ref (e.g. "heads/main").
func (c *Client) getRef(ctx context.Context, ref string) (string, error) {
	return c.getRefFor(ctx, c.Owner, c.Repo, ref)
}

// createRefFor creates a new git reference on the specified owner/repo.
func (c *Client) createRefFor(ctx context.Context, owner, repo, ref, sha string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo)
	body := map[string]string{
		"ref": "refs/" + ref,
		"sha": sha,
	}
	return c.doJSON(ctx, http.MethodPost, path, body, nil)
}

// createRef creates a new git reference.
func (c *Client) createRef(ctx context.Context, ref, sha string) error {
	return c.createRefFor(ctx, c.Owner, c.Repo, ref, sha)
}

// deleteRefExplicit deletes a git reference on the specified owner/repo.
func (c *Client) deleteRefExplicit(ctx context.Context, owner, repo, ref string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/%s", owner, repo, ref)
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}

// deleteRef deletes a git reference. Returns the error; cleanup callers
// log it and proceed regardless.
func (c *Client) deleteRef(ctx context.Context, ref string) error {
	return c.deleteRefExplicit(ctx, c.Owner, c.Repo, ref)
}

// getContentsFor returns the blob SHA of a file at the given ref for the specified owner/repo.
func (c *Client) getContentsFor(ctx context.Context, owner, repo, filePath, ref string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath) + "?" + url.Values{"ref": {ref}}.Encode()
	var resp struct {
		SHA string `json:"sha"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

// getContents returns the blob SHA of a file at the given ref.
// filePath is not URL-escaped — it comes from the RegistryFilePath constant, not user input.
func (c *Client) getContents(ctx context.Context, filePath, ref string) (string, error) {
	return c.getContentsFor(ctx, c.Owner, c.Repo, filePath, ref)
}

// updateContentsFor updates (or creates) a file in the specified owner/repo.
// content is raw bytes; this method base64-encodes them before sending.
func (c *Client) updateContentsFor(ctx context.Context, owner, repo, filePath, branch string, content []byte, fileSHA, message string) error {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath)
	body := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"sha":     fileSHA,
		"branch":  branch,
	}
	return c.doJSON(ctx, http.MethodPut, path, body, nil)
}

// updateContents updates (or creates) a file in the repository.
// content is raw bytes; this method base64-encodes them before sending.
func (c *Client) updateContents(ctx context.Context, filePath, branch string, content []byte, fileSHA, message string) error {
	return c.updateContentsFor(ctx, c.Owner, c.Repo, filePath, branch, content, fileSHA, message)
}

// createPRFor creates a pull request on the specified owner/repo and returns its number and URL.
func (c *Client) createPRFor(ctx context.Context, owner, repo, head, base, title, body string) (PRResult, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)
	reqBody := map[string]string{
		"title": title,
		"head":  head,
		"base":  base,
		"body":  body,
	}
	var pr PRResult
	if err := c.doJSON(ctx, http.MethodPost, path, reqBody, &pr); err != nil {
		return PRResult{}, err
	}
	return pr, nil
}

// createPR creates a pull request and returns its number and URL.
func (c *Client) createPR(ctx context.Context, head, base, title, body string) (PRResult, error) {
	return c.createPRFor(ctx, c.Owner, c.Repo, head, base, title, body)
}

// createBranchWithRetryFor generates a unique branch name and creates the ref on the specified owner/repo,
// retrying up to maxBranchRetries times on 422 "Reference already exists".
func (c *Client) createBranchWithRetryFor(ctx context.Context, owner, repo, sha, branchPrefix string) (string, error) {
	for attempt := range maxBranchRetries {
		suffix, err := core.RandomHex(16)
		if err != nil {
			return "", fmt.Errorf("generating branch suffix: %w", err)
		}
		branchName := branchPrefix + time.Now().UTC().Format("20060102T150405Z") + "-" + suffix

		err = c.createRefFor(ctx, owner, repo, "heads/"+branchName, sha)
		if err == nil {
			return branchName, nil
		}

		var ae *APIError
		if errors.As(err, &ae) && ae.StatusCode == 422 {
			if attempt < maxBranchRetries-1 {
				continue
			}
			return "", fmt.Errorf("branch name collision after %d attempts: %w", maxBranchRetries, err)
		}
		return "", fmt.Errorf("creating branch: %w", err)
	}
	panic("unreachable: loop always returns") // maxBranchRetries > 0
}

// createBranchWithRetry generates a unique branch name and creates the ref,
// retrying up to maxBranchRetries times on 422 "Reference already exists".
func (c *Client) createBranchWithRetry(ctx context.Context, sha string, branchPrefix string) (string, error) {
	return c.createBranchWithRetryFor(ctx, c.Owner, c.Repo, sha, branchPrefix)
}

// updateContentsWithRetryFor updates a file on the specified owner/repo, retrying once on 409
// (stale file SHA) by re-fetching the SHA.
func (c *Client) updateContentsWithRetryFor(ctx context.Context, owner, repo, filePath, branch string, content []byte, fileSHA, message string) error {
	err := c.updateContentsFor(ctx, owner, repo, filePath, branch, content, fileSHA, message)
	if err == nil {
		return nil
	}

	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 409 {
		return fmt.Errorf("updating file: %w", err)
	}

	// Re-fetch SHA from the branch (not "main") on the same owner/repo, and retry once.
	newSHA, fetchErr := c.getContentsFor(ctx, owner, repo, filePath, branch)
	if fetchErr != nil {
		return fmt.Errorf("re-fetching file SHA after 409: %w", fetchErr)
	}

	if retryErr := c.updateContentsFor(ctx, owner, repo, filePath, branch, content, newSHA, message); retryErr != nil {
		return fmt.Errorf("updating file (retry): %w", retryErr)
	}
	return nil
}

// updateContentsWithRetry updates the registry file, retrying once on 409
// (stale file SHA) by re-fetching the SHA.
func (c *Client) updateContentsWithRetry(ctx context.Context, filePath, branch string, content []byte, fileSHA, message string) error {
	return c.updateContentsWithRetryFor(ctx, c.Owner, c.Repo, filePath, branch, content, fileSHA, message)
}

// forkRepo creates a fork of owner/repo under the authenticated user's account.
// GitHub returns 202 for new forks and 200 for existing forks — both are 2xx success.
func (c *Client) forkRepo(ctx context.Context, owner, repo string) error {
	path := fmt.Sprintf("/repos/%s/%s/forks", owner, repo)
	return c.doJSON(ctx, http.MethodPost, path, map[string]string{}, nil)
}

// waitForFork polls GET /repos/{forkOwner}/{repo} until the fork is ready.
// Fails fast on non-404 errors.
func (c *Client) waitForFork(ctx context.Context, forkOwner, repo string) error {
	for attempt := range forkMaxPollAttempts {
		path := fmt.Sprintf("/repos/%s/%s", forkOwner, repo)
		err := c.doJSON(ctx, http.MethodGet, path, nil, nil)
		if err == nil {
			return nil
		}

		var ae *APIError
		if errors.As(err, &ae) && ae.StatusCode == 404 {
			if attempt < forkMaxPollAttempts-1 {
				select {
				case <-ctx.Done():
					return &ForkError{Phase: "poll", Wrapped: ctx.Err()}
				case <-time.After(forkPollInterval):
				}
				continue
			}
			return &ForkError{Phase: "poll", Wrapped: fmt.Errorf("fork not ready after %d attempts", forkMaxPollAttempts)}
		}
		// Non-404 error — fail fast.
		return &ForkError{Phase: "poll", Wrapped: err}
	}
	panic("unreachable: loop always returns") // forkMaxPollAttempts > 0
}

// syncFork calls merge-upstream to bring the fork's main up to date with upstream.
// Non-fatal on failure: 422 (already up to date) is silent success;
// all other non-2xx are logged and swallowed.
func (c *Client) syncFork(ctx context.Context, forkOwner, repo string) {
	path := fmt.Sprintf("/repos/%s/%s/merge-upstream", forkOwner, repo)
	body := map[string]string{"branch": "main"}
	err := c.doJSON(ctx, http.MethodPost, path, body, nil)
	if err == nil {
		return
	}
	var ae *APIError
	if errors.As(err, &ae) && ae.StatusCode == 422 {
		return // already up to date
	}
	log.Printf("warning: syncFork: %s", core.SanitizeForLog(err.Error()))
}

// createForkFilePR forks the upstream repo, pushes changes to the fork, and opens a cross-repo PR.
// c.Owner is never mutated — all calls use explicit owner parameters.
func (c *Client) createForkFilePR(ctx context.Context, filePath string, content []byte, branchPrefix, title, body string) (PRResult, error) {
	// 1. Fork the upstream repo.
	if err := c.forkRepo(ctx, c.Owner, c.Repo); err != nil {
		return PRResult{}, &ForkError{Phase: "create", Wrapped: err}
	}

	// 2. Wait for fork to be ready.
	if err := c.waitForFork(ctx, c.username, c.Repo); err != nil {
		return PRResult{}, err // already a *ForkError
	}

	// 3. Sync fork's main from upstream (non-fatal).
	c.syncFork(ctx, c.username, c.Repo)

	// 4. Get fork's main SHA.
	forkMainSHA, err := c.getRefFor(ctx, c.username, c.Repo, "heads/main")
	if err != nil {
		return PRResult{}, fmt.Errorf("getting fork main ref: %w", err)
	}

	// 5. Create branch on fork.
	branchName, err := c.createBranchWithRetryFor(ctx, c.username, c.Repo, forkMainSHA, branchPrefix)
	if err != nil {
		return PRResult{}, err
	}

	// Cleanup: on any subsequent failure, delete the branch on the fork.
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if delErr := c.deleteRefExplicit(cleanupCtx, c.username, c.Repo, "heads/"+branchName); delErr != nil {
			log.Printf("warning: failed to clean up fork branch %s: %s", branchName, core.SanitizeForLog(delErr.Error()))
		}
	}

	// 6. Get file SHA from fork's main.
	fileSHA, err := c.getContentsFor(ctx, c.username, c.Repo, filePath, "main")
	if err != nil {
		cleanup()
		return PRResult{}, fmt.Errorf("getting file SHA from fork: %w", err)
	}

	// 7. Update file on fork branch (with one retry on 409).
	if err := c.updateContentsWithRetryFor(ctx, c.username, c.Repo, filePath, branchName, content, fileSHA, title); err != nil {
		cleanup()
		return PRResult{}, err
	}

	// 8. Create cross-repo PR on upstream.
	pr, err := c.createPRFor(ctx, c.Owner, c.Repo, c.username+":"+branchName, "main", title, body)
	if err != nil {
		cleanup()
		return PRResult{}, fmt.Errorf("creating pull request: %w", err)
	}

	return pr, nil
}

// CreateRegistryPR creates a branch, updates the registry file, and opens a PR.
// Returns the PR number and URL on success.
func (c *Client) CreateRegistryPR(ctx context.Context, content []byte, title string) (PRResult, error) {
	if len(content) == 0 {
		return PRResult{}, fmt.Errorf("no registry content to submit")
	}
	if c.username == "" {
		return PRResult{}, fmt.Errorf("client username not set; cannot perform fork-based PR")
	}
	return c.createForkFilePR(ctx, RegistryFilePath, content, "registry-update-", title, "Registry update submitted via RHG Authenticator")
}

// CreateRevocationPR creates a branch, updates the revocation list, and opens a PR.
func (c *Client) CreateRevocationPR(ctx context.Context, content []byte, hash string) (PRResult, error) {
	if len(content) == 0 {
		return PRResult{}, fmt.Errorf("no revocation content to submit")
	}
	if c.username == "" {
		return PRResult{}, fmt.Errorf("client username not set; cannot perform fork-based PR")
	}

	shortHash := hash
	if len(shortHash) > 16 {
		shortHash = shortHash[:16]
	}
	branchPrefix := "revoke-" + shortHash + "-"
	title := fmt.Sprintf("Revoke credential %s", shortHash)
	body := fmt.Sprintf("Revoke credential with payload hash: %s", hash)

	return c.createForkFilePR(ctx, revocationPath, content, branchPrefix, title, body)
}
