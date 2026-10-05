//go:build !darwin

package update

// swapBundles is unavailable off macOS.
func swapBundles(_, _ string) error { return errUnsupported }

// relaunch is unavailable off macOS.
func relaunch(string) error { return errUnsupported }
