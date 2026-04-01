package registry

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const (
	// DefaultRegistryURL is the canonical remote source for the key registry.
	DefaultRegistryURL = "https://verify.royalhouseofgeorgia.ge/keys/registry.json"

	// DefaultRevocationURL is the canonical remote source for the revocation list.
	DefaultRevocationURL = "https://verify.royalhouseofgeorgia.ge/keys/revocations.json"

	// FetchTimeout is the maximum time allowed for a remote registry fetch.
	FetchTimeout = 10 * time.Second

	// maxRegistryBytes caps the response body to prevent memory exhaustion.
	maxRegistryBytes = 1 << 20 // 1 MiB
)

// FetchRegistry fetches the registry from the remote server only.
// Returns error if the fetch fails — no fallback to cache or embedded.
func FetchRegistry(remoteURL string) (core.Registry, error) {
	body, err := fetchRemote(remoteURL)
	if err != nil {
		return core.Registry{}, fmt.Errorf("registry fetch failed: %w", err)
	}
	reg, err := core.ValidateRegistry(body)
	if err != nil {
		return core.Registry{}, fmt.Errorf("registry validation failed: %w", err)
	}
	return reg, nil
}

// readLimitedBody reads the response body up to maxBytes. Returns an error if
// the body exceeds the limit.
func readLimitedBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d byte limit", maxBytes)
	}
	return body, nil
}

// Security note: uses default TLS (system CA bundle). Certificate pinning is
// intentionally omitted — it breaks on cert rotation and requires app updates.
// Registry integrity is ultimately verified by matching signing keys against
// the registry, not by TLS alone.
var registryClient = &http.Client{Timeout: FetchTimeout, CheckRedirect: core.SafeRedirect}

// fetchRemote does an HTTP GET with timeout and body size limit.
func fetchRemote(url string) ([]byte, error) {
	client := registryClient

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("unexpected Content-Type: %q", core.SanitizeForLog(ct))
	}

	return readLimitedBody(resp, maxRegistryBytes)
}

// fetchRemoteAllowNotFound does an HTTP GET like fetchRemote but returns
// nil, nil on 404 (resource may not exist yet). Non-404 errors are hard failures.
func fetchRemoteAllowNotFound(url string) ([]byte, error) {
	client := registryClient

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Content-Type: accept both application/json and application/vnd.github.raw+json
	// (GitHub Contents API may return the latter)
	ct := resp.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr != nil || (mediaType != "application/json" && mediaType != "application/vnd.github.raw+json") {
		return nil, fmt.Errorf("unexpected Content-Type: %q", core.SanitizeForLog(ct))
	}

	return readLimitedBody(resp, maxRegistryBytes)
}

// FetchRevocationList fetches and validates the revocation list.
// Returns an empty list (not error) on 404 — the file may not exist yet.
func FetchRevocationList(remoteURL string) (*core.RevocationList, error) {
	body, err := fetchRemoteAllowNotFound(remoteURL)
	if err != nil {
		return nil, fmt.Errorf("revocation list fetch failed: %w", err)
	}
	if body == nil {
		// 404 — return empty list
		return &core.RevocationList{Revocations: []core.RevocationEntry{}}, nil
	}
	list, err := core.ValidateRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("revocation list validation failed: %w", err)
	}
	return list, nil
}

// FindMatchingAuthority finds the authority name for a given public key in the registry.
// Checks date range against today's date.
func FindMatchingAuthority(reg core.Registry, pubKey [32]byte) (string, error) {
	return FindMatchingAuthorityAt(reg, pubKey, time.Now().UTC().Format("2006-01-02"))
}

// FindMatchingEntryAt returns the full KeyEntry for a matching public key and date.
// Returns nil if no match found.
func FindMatchingEntryAt(reg core.Registry, pubKey [32]byte, date string) *core.KeyEntry {
	for i := range reg.Keys {
		decoded, err := core.DecodePublicKey(reg.Keys[i])
		if err != nil {
			continue
		}
		if decoded != pubKey {
			continue
		}
		if !core.IsDateInRange(date, reg.Keys[i]) {
			continue
		}
		return &reg.Keys[i]
	}
	return nil
}

// FindMatchingAuthorityAt is like FindMatchingAuthority but uses a specific date
// instead of time.Now(). Useful for testing.
func FindMatchingAuthorityAt(reg core.Registry, pubKey [32]byte, date string) (string, error) {
	entry := FindMatchingEntryAt(reg, pubKey, date)
	if entry == nil {
		return "", fmt.Errorf("no active registry entry matches the YubiKey public key")
	}
	return entry.Authority, nil
}
