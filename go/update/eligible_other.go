//go:build !darwin

package update

// currentBundleEligible always reports ineligible off macOS.
func currentBundleEligible() (bundle string, ok bool, reason string) {
	return "", false, reasonUnsupported
}
