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

