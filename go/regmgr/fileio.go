package regmgr

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// ReadRegistry reads and validates a registry from a local JSON file.
func ReadRegistry(path string) (core.Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return core.Registry{}, fmt.Errorf("reading registry file: %w", err)
	}
	return core.ValidateRegistry(data)
}

// MarshalRegistry marshals a registry to formatted JSON bytes and validates the output.
// Returns JSON with 2-space indent and a trailing newline.
func MarshalRegistry(reg core.Registry) ([]byte, error) {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling registry: %w", err)
	}
	data = append(data, '\n')

	if _, err := core.ValidateRegistry(data); err != nil {
		return nil, fmt.Errorf("registry validation failed: %w", err)
	}
	return data, nil
}

// WriteRegistry marshals a registry to JSON and writes it atomically to the given path.
// The output is validated before writing to prevent persisting invalid data.
func WriteRegistry(path string, reg core.Registry) error {
	data, err := MarshalRegistry(reg)
	if err != nil {
		return err
	}

	// Atomic write via temp+rename.
	suffix, err := core.RandomHex(16)
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
