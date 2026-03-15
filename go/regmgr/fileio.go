package regmgr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

const (
	// fetchTimeout is the maximum time allowed for a remote registry fetch.
	fetchTimeout = 10 * time.Second

	// maxRegistryBytes caps the response body to prevent memory exhaustion.
	maxRegistryBytes = 1 << 20 // 1 MiB
)

// FetchRegistry fetches a registry from the given URL via HTTP GET.
// It enforces a 10s timeout, 1 MiB body limit, and application/json Content-Type.
func FetchRegistry(url string) (core.Registry, error) {
	client := &http.Client{Timeout: fetchTimeout}

	resp, err := client.Get(url)
	if err != nil {
		return core.Registry{}, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return core.Registry{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return core.Registry{}, fmt.Errorf("unexpected Content-Type: %q", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBytes))
	if err != nil {
		return core.Registry{}, fmt.Errorf("reading response body: %w", err)
	}

	return core.ValidateRegistry(body)
}

// ReadRegistry reads and validates a registry from a local JSON file.
func ReadRegistry(path string) (core.Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return core.Registry{}, fmt.Errorf("reading registry file: %w", err)
	}
	return core.ValidateRegistry(data)
}

// WriteRegistry marshals a registry to JSON and writes it atomically to the given path.
// The output is validated before writing to prevent persisting invalid data.
func WriteRegistry(path string, reg core.Registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling registry: %w", err)
	}
	data = append(data, '\n')

	// Validate output before writing.
	if _, err := core.ValidateRegistry(data); err != nil {
		return fmt.Errorf("registry validation failed: %w", err)
	}

	// Atomic write via temp+rename.
	suffix, err := randomSuffix()
	if err != nil {
		return fmt.Errorf("generating temp suffix: %w", err)
	}
	tmpPath := path + ".tmp." + suffix
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

func randomSuffix() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
