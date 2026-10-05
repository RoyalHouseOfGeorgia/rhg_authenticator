//go:build !darwin

package update

// verifyBundle is unavailable off macOS.
func verifyBundle(_, _, _ string) error { return errUnsupported }

// bundleVersion is unavailable off macOS.
func bundleVersion(string) (string, error) { return "", errUnsupported }
