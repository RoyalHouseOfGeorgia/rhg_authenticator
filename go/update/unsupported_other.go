//go:build !darwin

package update

import (
	"errors"
	"fmt"
)

// errUnsupported is returned by every in-app update operation that only
// exists on macOS.
var errUnsupported = fmt.Errorf("in-app update: %w", errors.ErrUnsupported)
