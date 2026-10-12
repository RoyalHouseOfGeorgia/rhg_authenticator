//go:build darwin

package update

// verifyBundle authenticates the bundle at bundlePath with codesign and
// plutil against requirement; see verifier.
func verifyBundle(bundlePath, requirement, version string) error {
	return verifyBundleTools(bundlePath, requirement, version)
}

// bundleVersion returns the bundle's CFBundleShortVersionString. It does not
// authenticate the bundle.
func bundleVersion(bundlePath string) (string, error) {
	return plistVersion(bundlePath)
}
