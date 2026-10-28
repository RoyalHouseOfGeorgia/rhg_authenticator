//go:build !windows

package service

// platformReadOnlyErrors are the extra read-only filesystem errors beyond
// syscall.EROFS; there are none outside Windows.
var platformReadOnlyErrors []error
