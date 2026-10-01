package regmgr

import (
	"encoding/json"
	"fmt"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

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
