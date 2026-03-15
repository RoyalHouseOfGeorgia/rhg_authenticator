package registry

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const (
	// DefaultRegistryURL is the canonical remote source for the key registry.
	DefaultRegistryURL = "https://verify.royalhouseofgeorgia.ge/keys/registry.json"

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

// fetchRemote does an HTTP GET with timeout and body size limit.
func fetchRemote(url string) ([]byte, error) {
	client := &http.Client{Timeout: FetchTimeout}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return nil, fmt.Errorf("unexpected Content-Type: %q", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return body, nil
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
