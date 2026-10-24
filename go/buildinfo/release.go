//go:build !rhgfake

package buildinfo

// FakeBuild reports whether this is the rhgfake test build, which signs with
// a software card; it never ships.
const FakeBuild = false
