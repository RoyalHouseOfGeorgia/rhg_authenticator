//go:build darwin

package update

import (
	"os"

	"golang.org/x/sys/unix"
)

// accessWritable reports whether the current user may write to path.
func accessWritable(path string) error {
	return unix.Access(path, unix.W_OK)
}

// currentBundleEligible locates the running app's bundle and reports whether
// it can be updated in place (see eligible).
func currentBundleEligible() (bundle string, ok bool, reason string) {
	exe, err := os.Executable()
	if err != nil {
		return "", false, reasonNotBundle
	}
	home, _ := os.UserHomeDir()
	return eligibleFromExe(exe, home, accessWritable)
}
