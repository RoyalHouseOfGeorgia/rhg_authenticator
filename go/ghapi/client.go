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
	apiBaseURL       = "https://api.github.com"
	maxResponseBytes = 2 * 1024 * 1024 // 2 MiB
	clientTimeout    = 30 * time.Second
	maxBranchRetries = 3
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

// Client is a GitHub API client scoped to a single repository.
type Client struct {
	token      string
	HTTPClient *http.Client
	Owner      string
	Repo       string
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

// safeCheckRedirect strips the Authorization header when a redirect targets
// a host outside *.github.com. This prevents credential leakage if a GitHub
// API response redirects to a third-party host.
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	origHost := via[0].URL.Host
	targetHost := req.URL.Host

	// Copy headers from the original request (Go's default redirect policy
	// does this already, but be explicit).
	if targetHost != origHost && !isGitHubHost(targetHost) {
		delete(req.Header, "Authorization")
	}
	// Enforce the standard 10-redirect limit.
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// isGitHubHost reports whether host is "github.com" or a subdomain of it.
func isGitHubHost(host string) bool {
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

// doJSON performs an authenticated JSON API request.
// If body is non-nil it is marshaled to JSON. If result is non-nil, a
// successful (2xx) response body is unmarshaled into it.
func (c *Client) doJSON(ctx context.Context, method, urlPath string, body, result any) error {
	fullURL := apiBaseURL + urlPath

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


// getRef returns the SHA of the given ref (e.g. "heads/main").
func (c *Client) getRef(ctx context.Context, ref string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/%s", c.Owner, c.Repo, ref)
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

// createRef creates a new git reference.
func (c *Client) createRef(ctx context.Context, ref, sha string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs", c.Owner, c.Repo)
	body := map[string]string{
		"ref": "refs/" + ref,
		"sha": sha,
	}
	return c.doJSON(ctx, http.MethodPost, path, body, nil)
}

// deleteRef deletes a git reference. Returns the error; cleanup callers
// log it and proceed regardless.
func (c *Client) deleteRef(ctx context.Context, ref string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/%s", c.Owner, c.Repo, ref)
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}

// getContents returns the blob SHA of a file at the given ref.
// filePath is not URL-escaped — it comes from the RegistryFilePath constant, not user input.
func (c *Client) getContents(ctx context.Context, filePath, ref string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", c.Owner, c.Repo, filePath) + "?" + url.Values{"ref": {ref}}.Encode()
	var resp struct {
		SHA string `json:"sha"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	return resp.SHA, nil
}

// updateContents updates (or creates) a file in the repository.
// content is raw bytes; this method base64-encodes them before sending.
func (c *Client) updateContents(ctx context.Context, filePath, branch string, content []byte, fileSHA, message string) error {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", c.Owner, c.Repo, filePath)
	body := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"sha":     fileSHA,
		"branch":  branch,
	}
	return c.doJSON(ctx, http.MethodPut, path, body, nil)
}

// createPR creates a pull request and returns its number and URL.
func (c *Client) createPR(ctx context.Context, head, base, title, body string) (PRResult, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls", c.Owner, c.Repo)
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

// createFilePR creates a branch, updates a file, and opens a PR.
func (c *Client) createFilePR(ctx context.Context, filePath string, content []byte, branchPrefix, title, body string) (PRResult, error) {
	// 1. Get main branch SHA.
	mainSHA, err := c.getRef(ctx, "heads/main")
	if err != nil {
		return PRResult{}, fmt.Errorf("getting main ref: %w", err)
	}

	// 2. Create branch with retry on name collision.
	branchName, err := c.createBranchWithRetry(ctx, mainSHA, branchPrefix)
	if err != nil {
		return PRResult{}, err
	}

	// 3. All subsequent failures trigger best-effort branch cleanup.
	// Uses a detached context so cleanup succeeds even if the caller's context is cancelled.
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if delErr := c.deleteRef(cleanupCtx, "heads/"+branchName); delErr != nil {
			log.Printf("warning: failed to clean up branch %s: %v", branchName, delErr)
		}
	}

	// 4. Get file SHA on main.
	fileSHA, err := c.getContents(ctx, filePath, "main")
	if err != nil {
		cleanup()
		return PRResult{}, fmt.Errorf("getting file SHA: %w", err)
	}

	// 5. Update contents with one retry on 409 (stale SHA).
	if err := c.updateContentsWithRetry(ctx, filePath, branchName, content, fileSHA, title); err != nil {
		cleanup()
		return PRResult{}, err
	}

	// 6. Create PR.
	pr, err := c.createPR(ctx, branchName, "main", title, body)
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
	return c.createFilePR(ctx, RegistryFilePath, content, "registry-update-", title, "Registry update submitted via RHG Authenticator")
}

// CreateRevocationPR creates a branch, updates the revocation list, and opens a PR.
func (c *Client) CreateRevocationPR(ctx context.Context, content []byte, hash string) (PRResult, error) {
	if len(content) == 0 {
		return PRResult{}, fmt.Errorf("no revocation content to submit")
	}

	shortHash := hash
	if len(shortHash) > 16 {
		shortHash = shortHash[:16]
	}
	branchPrefix := "revoke-" + shortHash + "-"
	title := fmt.Sprintf("Revoke credential %s", shortHash)
	body := fmt.Sprintf("Revoke credential with payload hash: %s", hash)

	return c.createFilePR(ctx, revocationPath, content, branchPrefix, title, body)
}

// createBranchWithRetry generates a unique branch name and creates the ref,
// retrying up to maxBranchRetries times on 422 "Reference already exists".
func (c *Client) createBranchWithRetry(ctx context.Context, sha string, branchPrefix string) (string, error) {
	for attempt := range maxBranchRetries {
		suffix, err := core.RandomHex(16)
		if err != nil {
			return "", fmt.Errorf("generating branch suffix: %w", err)
		}
		branchName := branchPrefix + time.Now().UTC().Format("20060102T150405Z") + "-" + suffix

		err = c.createRef(ctx, "heads/"+branchName, sha)
		if err == nil {
			return branchName, nil
		}

		// Any 422 on createRef means the branch name collides (the name
		// format is always valid). Retry with a new suffix.
		var ae *APIError
		if errors.As(err, &ae) && ae.StatusCode == 422 {
			if attempt < maxBranchRetries-1 {
				continue
			}
			return "", fmt.Errorf("branch name collision after %d attempts: %w", maxBranchRetries, err)
		}
		return "", fmt.Errorf("creating branch: %w", err)
	}
	// Unreachable, but the compiler needs it.
	return "", fmt.Errorf("branch creation failed")
}

// updateContentsWithRetry updates the registry file, retrying once on 409
// (stale file SHA) by re-fetching the SHA.
func (c *Client) updateContentsWithRetry(ctx context.Context, filePath, branch string, content []byte, fileSHA, message string) error {
	err := c.updateContents(ctx, filePath, branch, content, fileSHA, message)
	if err == nil {
		return nil
	}

	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 409 {
		return fmt.Errorf("updating registry file: %w", err)
	}

	// Re-fetch SHA and retry once.
	newSHA, fetchErr := c.getContents(ctx, filePath, branch)
	if fetchErr != nil {
		return fmt.Errorf("re-fetching file SHA after 409: %w", fetchErr)
	}

	if retryErr := c.updateContents(ctx, filePath, branch, content, newSHA, message); retryErr != nil {
		return fmt.Errorf("updating registry file (retry): %w", retryErr)
	}
	return nil
}
