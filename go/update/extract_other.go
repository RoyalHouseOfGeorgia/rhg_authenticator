//go:build !unix

package update

// openNoFollow is unavailable on this platform; O_EXCL alone still refuses
// any pre-existing path, symlinks included.
const openNoFollow = 0
