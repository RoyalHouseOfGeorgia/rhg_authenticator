package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const (
	serviceName   = "rhg-authenticator"
	serviceKey    = "github-token"
	tokenFileName = "github_token.json"

	deviceCodeURL  = "https://github.com/login/device/code"
	accessTokenURL = "https://github.com/login/oauth/access_token"
	requiredScope  = "public_repo"

	defaultPollInterval = 5  // seconds, per RFC 8628 §3.5
	maxPollInterval     = 60 // seconds, cap for slow_down accumulation
	deviceFlowTimeout   = 10 * time.Second
)

// ClientID is the GitHub OAuth App client ID.
// This is public and safe to embed — device flow does not use a client secret.
//
// For production builds, set via:
//
//	go build -ldflags '-X github.com/royalhouseofgeorgia/rhg-authenticator/ghapi.ClientID=YOUR_ID'
//
// Declared as var (not const) so tests can override it directly.
var ClientID = "PLACEHOLDER"

// printableASCII50RE matches strings containing only printable ASCII (0x20-0x7E), 1-50 chars.
var printableASCII50RE = regexp.MustCompile(`^[\x20-\x7E]{1,50}$`)

// printableASCII100RE matches strings containing only printable ASCII, 1-100 chars.
var printableASCII100RE = regexp.MustCompile(`^[\x20-\x7E]{1,100}$`)

// Token represents a GitHub OAuth token with metadata.
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Scope       string    `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
}

// String returns a redacted representation of the token to prevent accidental
// exposure of the access token in logs or debug output.
func (t Token) String() string {
	return fmt.Sprintf(`Token{AccessToken:"[REDACTED]", TokenType:%q, Scope:%q}`, t.TokenType, t.Scope)
}

// GoString returns a redacted representation for fmt %#v formatting.
func (t Token) GoString() string {
	return t.String()
}

// DeviceCodeResponse holds the response from GitHub's device authorization endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// goos is the runtime OS, exposed as a variable so tests can override it.
var goos = runtime.GOOS

// maxTokenAge is the maximum lifetime for a stored OAuth token before
// it is considered expired and must be re-authenticated.
const maxTokenAge = 90 * 24 * time.Hour

// timeNow is the time source, overridable in tests.
// Tests MUST use t.Cleanup() to restore the original value.
var timeNow = time.Now

// Endpoint variables — tests override these to point at httptest servers.
var (
	deviceCodeEndpoint  = deviceCodeURL
	accessTokenEndpoint = accessTokenURL
	userAPIEndpoint     = apiBaseURL + "/user"
)

// LoadToken retrieves a stored GitHub token, trying the keyring first
// and falling back to a JSON file in configDir.
//
// Returns os.ErrNotExist (wrapped) when no valid token is found anywhere.
// Non-ErrKeyNotFound keyring errors are surfaced immediately (not swallowed).
func LoadToken(kr Keyring, configDir string) (Token, error) {
	val, err := kr.Get(serviceName, serviceKey)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return Token{}, fmt.Errorf("keyring access failed: %w", err)
	}
	if err == nil {
		var tok Token
		if jsonErr := json.Unmarshal([]byte(val), &tok); jsonErr == nil && tok.AccessToken != "" {
			return tok, nil
		}
		// Corrupt or empty JSON in keyring — fall through to file.
		log.Printf("warning: invalid token in keyring, falling back to file")
	}
	// Key not found in keyring — try file.
	return loadTokenFromFile(configDir)
}

// loadTokenFromFile attempts to read a token from the fallback JSON file.
func loadTokenFromFile(configDir string) (Token, error) {
	path := filepath.Join(configDir, tokenFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Token{}, fmt.Errorf("no stored token: %w", os.ErrNotExist)
		}
		return Token{}, fmt.Errorf("reading token file: %w", err)
	}

	// Zero-byte file — treat as missing.
	if len(data) == 0 {
		_ = os.Remove(path)
		return Token{}, fmt.Errorf("empty token file removed: %w", os.ErrNotExist)
	}

	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		_ = os.Remove(path)
		log.Printf("warning: removed corrupt token file from config directory: %v", err)
		return Token{}, fmt.Errorf("corrupt token file removed: %w", os.ErrNotExist)
	}
	if tok.AccessToken == "" {
		_ = os.Remove(path)
		return Token{}, fmt.Errorf("empty access token in file removed: %w", os.ErrNotExist)
	}
	return tok, nil
}

// SaveToken persists a token to the OS keyring. On Linux, if the keyring
// is unavailable, it falls back to an atomic file write in configDir.
//
// Security note: the file fallback stores the token in plaintext JSON with
// 0o600 permissions. This is the same trust model as gh CLI, gcloud, and aws
// CLI. At-rest encryption with a locally-stored key provides no additional
// protection if the user's home directory is compromised.
func SaveToken(kr Keyring, configDir string, tok Token) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	krErr := kr.Set(serviceName, serviceKey, string(data))
	if krErr == nil {
		return nil
	}

	if goos != "linux" {
		return fmt.Errorf("saving token to keychain: %w", krErr)
	}

	// Linux file fallback.
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	path := filepath.Join(configDir, tokenFileName)
	suffix, err := core.RandomHex(16)
	if err != nil {
		return fmt.Errorf("generating temp suffix: %w", err)
	}
	tmpPath := path + ".tmp." + suffix
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing temp token file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp token file: %w", err)
	}

	log.Printf("warning: keychain unavailable, token saved to config directory")
	return nil
}

// ClearToken removes the stored token from both the keyring and the
// fallback file. Errors from missing entries are ignored.
func ClearToken(kr Keyring, configDir string) error {
	var firstErr error

	krErr := kr.Delete(serviceName, serviceKey)
	if krErr != nil && !errors.Is(krErr, ErrKeyNotFound) {
		firstErr = krErr
	}

	path := filepath.Join(configDir, tokenFileName)
	rmErr := os.Remove(path)
	if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		if firstErr == nil {
			firstErr = rmErr
		}
	}

	return firstErr
}

// newAuthHTTPClient returns an HTTP client configured for OAuth endpoints.
func newAuthHTTPClient() *http.Client {
	return &http.Client{Timeout: deviceFlowTimeout, CheckRedirect: safeCheckRedirect}
}

// RequestDeviceCode initiates the OAuth device authorization flow with GitHub.
func RequestDeviceCode(ctx context.Context) (DeviceCodeResponse, error) {
	if ClientID == "PLACEHOLDER" {
		return DeviceCodeResponse{}, fmt.Errorf("OAuth ClientID not configured — set via -ldflags '-X github.com/royalhouseofgeorgia/rhg-authenticator/ghapi.ClientID=YOUR_ID' at build time")
	}

	form := url.Values{
		"client_id": {ClientID},
		"scope":     {requiredScope},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceCodeEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceCodeResponse{}, fmt.Errorf("creating device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := newAuthHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return DeviceCodeResponse{}, fmt.Errorf("requesting device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return DeviceCodeResponse{}, fmt.Errorf("reading device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Parse structured error fields if available; fall back to sanitized body.
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		msg := core.SanitizeForLog(string(body))
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			msg = core.SanitizeForLog(errResp.Error)
			if errResp.ErrorDescription != "" {
				msg += ": " + core.SanitizeForLog(errResp.ErrorDescription)
			}
		}
		return DeviceCodeResponse{}, fmt.Errorf("device code request failed (HTTP %d): %s", resp.StatusCode, msg)
	}

	var dcr DeviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		return DeviceCodeResponse{}, fmt.Errorf("parsing device code response: %w", err)
	}

	// Reject user codes containing control characters or excessively long values.
	if !printableASCII50RE.MatchString(dcr.UserCode) {
		return DeviceCodeResponse{}, fmt.Errorf("invalid user code format")
	}

	return dcr, nil
}

// hasRequiredScope checks whether the token scope includes "public_repo" or
// its superset "repo". An empty scope is accepted because some token types
// (e.g. fine-grained PATs) do not return a scope string.
func hasRequiredScope(scope string) bool {
	if scope == "" {
		// Fine-grained PATs and some token types do not return an
		// X-OAuth-Scopes header. Accept empty scope — GitHub enforces
		// permissions server-side. The token will fail on actual API
		// calls if it lacks the required access.
		return true
	}
	// GitHub returns comma-separated scopes; split on both comma and space for robustness.
	for _, s := range strings.FieldsFunc(scope, func(r rune) bool { return r == ',' || r == ' ' }) {
		if s == "public_repo" || s == "repo" {
			return true
		}
	}
	return false
}

// pollResponse is used internally to parse the token polling response which
// may contain either an access token or an error string.
type pollResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

// PollForToken polls GitHub's access token endpoint until the user authorizes
// the device, the code expires, or the context is cancelled.
func PollForToken(ctx context.Context, deviceCode string, interval, expiresIn int) (Token, error) {
	return pollForTokenInternal(ctx, deviceCode, interval, expiresIn, realSleep)
}

// realSleep waits for the given duration or until the context is cancelled.
func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pollForTokenInternal is the testable core of PollForToken.
// sleepFn controls the wait between polls — tests inject an instant sleep.
func pollForTokenInternal(ctx context.Context, deviceCode string, interval, expiresIn int, sleepFn func(context.Context, time.Duration) error) (Token, error) {
	if expiresIn <= 0 {
		return Token{}, fmt.Errorf("expiresIn must be positive, got %d", expiresIn)
	}
	if interval <= 0 {
		interval = defaultPollInterval
	}
	// Cap expiresIn to prevent a malicious server from holding the poll
	// loop open indefinitely.
	const maxExpiresIn = 1800
	if expiresIn > maxExpiresIn {
		expiresIn = maxExpiresIn
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(expiresIn)*time.Second)
	defer cancel()

	client := newAuthHTTPClient()

	for {
		if err := sleepFn(ctx, time.Duration(interval)*time.Second); err != nil {
			return Token{}, err
		}

		form := url.Values{
			"client_id":   {ClientID},
			"device_code": {deviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return Token{}, fmt.Errorf("creating poll request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return Token{}, ctx.Err()
			}
			return Token{}, fmt.Errorf("polling for token: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		resp.Body.Close()
		if readErr != nil {
			return Token{}, fmt.Errorf("reading poll response: %w", readErr)
		}

		var pr pollResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return Token{}, fmt.Errorf("parsing poll response: %w", err)
		}

		if pr.Error != "" {
			switch pr.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5
				if interval > maxPollInterval {
					interval = maxPollInterval
				}
				continue
			case "expired_token":
				return Token{}, fmt.Errorf("device code expired")
			case "access_denied":
				return Token{}, fmt.Errorf("access denied by user")
			default:
				return Token{}, fmt.Errorf("unexpected OAuth error: %s", core.SanitizeForLog(pr.Error))
			}
		}

		if pr.AccessToken != "" {
			if !hasRequiredScope(pr.Scope) {
				return Token{}, fmt.Errorf("token missing required scope: public_repo")
			}
			return Token{
				AccessToken: pr.AccessToken,
				TokenType:   pr.TokenType,
				Scope:       pr.Scope,
				CreatedAt:   time.Now().UTC(),
			}, nil
		}

		return Token{}, fmt.Errorf("poll response has neither access_token nor error")
	}
}

// ValidateToken checks whether a token is still valid by calling the
// GitHub /user endpoint. Returns the GitHub login on success.
func ValidateToken(ctx context.Context, tok Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userAPIEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating validate request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := newAuthHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("validating token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("reading validate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := core.SanitizeForLog(string(body))
		// Try to extract a JSON message field.
		var errBody struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &errBody) == nil && errBody.Message != "" {
			msg = core.SanitizeForLog(errBody.Message)
		}
		return "", &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	var user struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("parsing user response: %w", err)
	}
	if user.Login == "" {
		return "", fmt.Errorf("GitHub user response missing login field")
	}
	if !printableASCII100RE.MatchString(user.Login) {
		return "", fmt.Errorf("invalid GitHub login format")
	}
	return user.Login, nil
}

// isTokenExpired reports whether a token has exceeded maxTokenAge.
// Tokens with a zero CreatedAt are treated as expired (defense-in-depth
// for manually edited token files).
func isTokenExpired(tok Token) bool {
	return tok.CreatedAt.IsZero() || timeNow().Sub(tok.CreatedAt) > maxTokenAge
}

// RestoreSession attempts to load and validate a stored token.
// Returns the token, username, login status, offline status, and any error.
//
// When no token is stored, loggedIn is false with nil error.
// When the token is valid and reachable, loggedIn is true and offline is false.
// When the token exists but GitHub is unreachable, loggedIn is true, offline is true.
// When the token is rejected (401), the token is cleared and loggedIn is false.
func RestoreSession(ctx context.Context, kr Keyring, configDir string) (token Token, username string, loggedIn bool, offline bool, err error) {
	tok, err := LoadToken(kr, configDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Token{}, "", false, false, nil
		}
		return Token{}, "", false, false, err
	}

	// Enforce local TTL — forces re-authentication for old tokens.
	if isTokenExpired(tok) {
		_ = ClearToken(kr, configDir)
		return Token{}, "", false, false, nil
	}

	login, valErr := ValidateToken(ctx, tok)
	if valErr == nil {
		return tok, login, true, false, nil
	}

	if IsUnauthorized(valErr) {
		_ = ClearToken(kr, configDir)
		return Token{}, "", false, false, nil
	}

	// Network error, timeout, etc. — assume offline but keep the token.
	return tok, "", true, true, nil
}
