package buildinfo

// Version is set at build time via -ldflags. It defaults to "dev" for
// local builds and is overridden by the release pipeline (e.g. "v1.2.3").
var Version = "dev"

// IsRelease reports whether Version looks like a semantic version tag
// (starts with 'v' followed by a digit).
func IsRelease() bool {
	return len(Version) > 1 && Version[0] == 'v' && Version[1] >= '0' && Version[1] <= '9'
}

// IsDebug reports whether the build is NOT a tagged release.
func IsDebug() bool {
	return !IsRelease()
}
