package registry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
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

// FetchRegistry fetches the registry with fallback chain: remote -> cache -> embedded.
// cachePath is where to cache the remote result (e.g., <dataDir>/registry.cache.json).
// embedded is the go:embed'd registry bytes.
// Returns the registry, the source name ("remote", "cache", or "embedded"), and any error.
func FetchRegistry(remoteURL, cachePath string, embedded []byte) (core.Registry, string, error) {
	// 1. Try remote fetch.
	// Intentional: validate BEFORE caching so only valid registries are persisted.
	if body, err := fetchRemote(remoteURL); err == nil {
		if parsed, err := core.ValidateRegistry(body); err == nil {
			// Cache the validated result (best-effort, atomic via temp+rename).
			if suffix, err := randomCacheSuffix(); err == nil {
				tmpPath := cachePath + ".tmp." + suffix
				if err := os.WriteFile(tmpPath, body, 0o600); err == nil {
					_ = os.Rename(tmpPath, cachePath)
				} else {
					_ = os.Remove(tmpPath)
				}
			}
			return parsed, "remote", nil
		}
		// Remote returned invalid registry — fall through.
	}

	// 2. Try cached file.
	if data, err := os.ReadFile(cachePath); err == nil {
		if parsed, err := core.ValidateRegistry(data); err == nil {
			return parsed, "cache", nil
		}
		// Corrupted cache — fall through to embedded.
	}

	// 3. Try embedded.
	if parsed, err := core.ValidateRegistry(embedded); err == nil {
		return parsed, "embedded", nil
	}

	return core.Registry{}, "", fmt.Errorf("all registry sources failed")
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
	return FindMatchingAuthorityAt(reg, pubKey, time.Now().Format("2006-01-02"))
}

// FindMatchingAuthorityAt is like FindMatchingAuthority but uses a specific date
// instead of time.Now(). Useful for testing.
func FindMatchingAuthorityAt(reg core.Registry, pubKey [32]byte, date string) (string, error) {
	for _, entry := range reg.Keys {
		decoded, err := core.DecodePublicKey(entry)
		if err != nil {
			continue
		}
		if decoded != pubKey {
			continue
		}
		if !core.IsDateInRange(date, entry) {
			continue
		}
		return entry.Authority, nil
	}

	return "", fmt.Errorf("no active registry entry matches the YubiKey public key")
}

func randomCacheSuffix() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
