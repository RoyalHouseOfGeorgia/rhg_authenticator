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
	DefaultOwner      = "RoyalHouseOfGeorgia"
	DefaultRepo       = "rhg_authenticator"
	RegistryFilePath  = "verify/keys/registry.json"
	revocationPath    = "verify/keys/revocations.json"
	defaultAPIBaseURL = "https://api.github.com"
	maxResponseBytes  = 2 * 1024 * 1024 // 2 MiB
	clientTimeout     = 30 * time.Second
	maxBranchRetries  = 3
)

// ErrAlreadyRevoked is returned by CreateRevocationPR when the hash is already
// present in the upstream revocation list.
var ErrAlreadyRevoked = errors.New("credential is already revoked")

// ErrRevocationPending is returned by CreateRevocationPR when an open
// same-repository revocation PR for the hash already exists.
var ErrRevocationPending = errors.New("a revocation pull request is already open")

// ErrNoWriteAccess is returned by CreateRegistryPR and CreateRevocationPR when
// GitHub reports that the authenticated user cannot push to the repository
// (i.e. is not a collaborator with write access).
var ErrNoWriteAccess = errors.New("no write access to repository")

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

// UserMessage maps API errors to safe, user-friendly messages suitable for
// display in dialogs. It never includes err's text, so internal details
// (hosts, response bodies) are not leaked to the user.
func UserMessage(err error) string {
	if errors.Is(err, ErrAlreadyRevoked) {
		return "This credential is already revoked."
	}
	if errors.Is(err, ErrRevocationPending) {
		return "A revocation for this credential is already awaiting review on GitHub."
	}
	if errors.Is(err, ErrNoWriteAccess) {
		return "Your GitHub account can't submit changes to this repository. Ask the maintainer to add you as a collaborator."
	}
	if IsRateLimited(err) {
		return "GitHub rate limit reached. Try again in a few minutes."
	}
	if IsForbidden(err) {
		return "Permission denied. Check your GitHub account permissions."
	}
	// Network/timeout errors
	return "An error occurred. Please try again later."
}

// Client is a GitHub API client scoped to a single repository.
type Client struct {
	token      string
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

// FetchUpstreamFile returns the decoded content of filePath on the upstream
// repository's main branch. Files the contents API does not return inline
// (encoding other than "base64", e.g. "none" for files over 1 MB) are an error.
// filePath is not URL-escaped — callers pass package constants, not user input.
func (c *Client) FetchUpstreamFile(ctx context.Context, filePath string) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", c.Owner, c.Repo, filePath) + "?" + url.Values{"ref": {"main"}}.Encode()
	var resp struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Encoding != "base64" {
		return nil, fmt.Errorf("unsupported content encoding %q for %s", core.SanitizeForError(resp.Encoding), filePath)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", filePath, err)
	}
	return data, nil
}

// getContents returns the blob SHA of a file at the given ref.
// filePath is not URL-escaped — callers pass package constants, not user input.
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

// createBranchWithRetry generates a unique branch name and creates the ref,
// retrying up to maxBranchRetries times on 422 "Reference already exists".
func (c *Client) createBranchWithRetry(ctx context.Context, sha, branchPrefix string) (string, error) {
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

// updateContentsWithRetry updates a file, retrying once on 409 (stale file
// SHA) by re-fetching the SHA from branch.
func (c *Client) updateContentsWithRetry(ctx context.Context, filePath, branch string, content []byte, fileSHA, message string) error {
	err := c.updateContents(ctx, filePath, branch, content, fileSHA, message)
	if err == nil {
		return nil
	}

	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 409 {
		return fmt.Errorf("updating file: %w", err)
	}

	// Re-fetch SHA from the branch (not "main") and retry once.
	newSHA, fetchErr := c.getContents(ctx, filePath, branch)
	if fetchErr != nil {
		return fmt.Errorf("re-fetching file SHA after 409: %w", fetchErr)
	}

	if retryErr := c.updateContents(ctx, filePath, branch, content, newSHA, message); retryErr != nil {
		return fmt.Errorf("updating file (retry): %w", retryErr)
	}
	return nil
}

// checkWriteAccess returns ErrNoWriteAccess when GitHub reports that the
// authenticated user cannot push to c.Owner/c.Repo. A response without a
// permissions object is treated as "unknown" and allowed through: the
// subsequent branch creation fails with a 403/404 in that case anyway.
func (c *Client) checkWriteAccess(ctx context.Context) error {
	path := fmt.Sprintf("/repos/%s/%s", c.Owner, c.Repo)
	var resp struct {
		Permissions *struct {
			Push bool `json:"push"`
		} `json:"permissions"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return fmt.Errorf("checking repository access: %w", err)
	}
	if resp.Permissions != nil && !resp.Permissions.Push {
		return ErrNoWriteAccess
	}
	return nil
}

// createRepoFilePR creates a branch in c.Owner/c.Repo off main, commits
// content to filePath on it, and opens a same-repository PR into main.
// Requires write (collaborator) access; main is protected by a ruleset, so
// the PR still needs maintainer review to merge. If any step after branch
// creation fails, the branch is deleted on a best-effort basis.
func (c *Client) createRepoFilePR(ctx context.Context, filePath string, content []byte, branchPrefix, title, body string) (PRResult, error) {
	// 1. Fail fast with a clear message when the user lacks write access.
	if err := c.checkWriteAccess(ctx); err != nil {
		return PRResult{}, err
	}

	// 2. Get main's SHA.
	mainSHA, err := c.getRef(ctx, "heads/main")
	if err != nil {
		return PRResult{}, fmt.Errorf("getting main ref: %w", err)
	}

	// 3. Create the branch.
	branchName, err := c.createBranchWithRetry(ctx, mainSHA, branchPrefix)
	if err != nil {
		return PRResult{}, err
	}

	// Cleanup: on any subsequent failure, delete the branch. Uses a fresh
	// context so a cancelled/expired ctx does not prevent cleanup.
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if delErr := c.deleteRef(cleanupCtx, "heads/"+branchName); delErr != nil {
			log.Printf("warning: failed to clean up branch %s: %s", branchName, core.SanitizeForLog(delErr.Error()))
		}
	}

	// 4. Get the file's blob SHA on the new branch.
	fileSHA, err := c.getContents(ctx, filePath, branchName)
	if err != nil {
		cleanup()
		return PRResult{}, fmt.Errorf("getting file SHA: %w", err)
	}

	// 5. Update the file on the branch (with one retry on 409).
	if err := c.updateContentsWithRetry(ctx, filePath, branchName, content, fileSHA, title); err != nil {
		cleanup()
		return PRResult{}, err
	}

	// 6. Open the PR.
	pr, err := c.createPR(ctx, branchName, "main", title, body)
	if err != nil {
		cleanup()
		return PRResult{}, fmt.Errorf("creating pull request: %w", err)
	}

	return pr, nil
}

// CreateRegistryPR creates a branch in the upstream repository, updates the
// registry file on it, and opens a same-repository PR into main.
// Returns the PR number and URL on success, or ErrNoWriteAccess if the
// authenticated user is not a collaborator with write access.
func (c *Client) CreateRegistryPR(ctx context.Context, content []byte, title string) (PRResult, error) {
	if len(content) == 0 {
		return PRResult{}, fmt.Errorf("no registry content to submit")
	}
	return c.createRepoFilePR(ctx, RegistryFilePath, content, "registry-update-", title, "Registry update submitted via RHG Authenticator")
}

// CreateRevocationPR appends a revocation entry for hash to the upstream
// revocation list on main and opens a same-repository PR with the result.
// The list is always rebuilt from upstream main (never a locally cached copy)
// so that revocations merged since the caller last fetched are preserved.
// Returns ErrAlreadyRevoked if hash is already in the upstream list, and
// ErrRevocationPending if an open revocation PR for it already exists, and
// ErrNoWriteAccess if the authenticated user cannot push to the repository.
// hash must be a 64-character hex SHA-256 (any case); revokedOn is a YYYY-MM-DD date.
func (c *Client) CreateRevocationPR(ctx context.Context, hash, revokedOn string) (PRResult, error) {
	hash = strings.ToLower(hash) // same normalisation as core.ValidateRevocationList
	if !core.IsPayloadHash(hash) {
		return PRResult{}, fmt.Errorf("invalid payload hash: must be 64 hex characters")
	}

	current, err := c.FetchUpstreamFile(ctx, revocationPath)
	if err != nil {
		return PRResult{}, fmt.Errorf("fetching upstream revocation list: %w", err)
	}
	list, err := core.ValidateRevocationList(current)
	if err != nil {
		return PRResult{}, fmt.Errorf("validating upstream revocation list: %w", err)
	}

	if core.IsRevoked(hash, core.BuildRevocationSet(list)) {
		return PRResult{}, ErrAlreadyRevoked
	}
	// Fail open: a redundant PR is harmless, a blocked revocation is not.
	pending, err := c.findOpenRevocationPR(ctx, hash)
	if err != nil {
		log.Printf("warning: open-PR lookup failed: %s", core.SanitizeForLog(err.Error()))
	} else if pending {
		return PRResult{}, ErrRevocationPending
	}

	updated := core.AppendRevocationEntry(list, hash, revokedOn)
	content, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return PRResult{}, fmt.Errorf("marshaling revocation list: %w", err)
	}
	content = append(content, '\n')

	shortHash := hash[:16]
	title := fmt.Sprintf("Revoke credential %s", shortHash)
	body := fmt.Sprintf("Revoke credential with payload hash: %s", hash)

	return c.createRepoFilePR(ctx, revocationPath, content, revocationBranchPrefix(hash), title, body)
}

// findOpenRevocationPR reports whether c.Owner/c.Repo has an open PR whose
// head branch lives in c.Owner/c.Repo itself and is a revocation branch for
// hash (as named by CreateRevocationPR). hash must be a validated, lowercased
// payload hash.
//
// Any operator's pending same-repo PR counts, regardless of author. A PR from
// a fork never counts, even with a matching branch name: the repository is
// public and the hash is derivable from any credential QR code, so anyone
// could open a fork PR named after it to suppress a real revocation. Leftover
// PRs from the old fork-based flow are therefore unmatched too, which at worst
// yields a redundant PR (fail-open).
func (c *Client) findOpenRevocationPR(ctx context.Context, hash string) (bool, error) {
	// Only the first page is checked: the repo has a handful of open PRs at
	// most, far below per_page.
	path := fmt.Sprintf("/repos/%s/%s/pulls", c.Owner, c.Repo) + "?" + url.Values{"state": {"open"}, "per_page": {"100"}}.Encode()
	var pulls []struct {
		Head struct {
			Ref string `json:"ref"`
			// Value, not pointer: a null repo (deleted fork) decodes to empty.
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &pulls); err != nil {
		return false, fmt.Errorf("listing open pull requests: %w", err)
	}
	prefix := revocationBranchPrefix(hash)
	thisRepo := c.Owner + "/" + c.Repo
	for _, p := range pulls {
		if strings.HasPrefix(p.Head.Ref, prefix) && strings.EqualFold(p.Head.Repo.FullName, thisRepo) {
			return true, nil
		}
	}
	return false, nil
}

// revocationBranchPrefix is the branch prefix CreateRevocationPR uses for
// hash; findOpenRevocationPR matches on it, so both must share this helper.
func revocationBranchPrefix(hash string) string {
	return "revoke-" + hash[:16] + "-"
}
