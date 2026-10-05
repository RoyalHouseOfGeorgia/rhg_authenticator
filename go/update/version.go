package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version strings reach the updater in two spellings: release tags and
// buildinfo use "v1.5.0" (or legacy two-part "v1.4"), while a bundle's
// Info.plist uses "1.5.0". All comparisons go through parseSemver, which
// accepts both and treats a missing patch component as 0.

// normalizeVersion returns the canonical "X.Y.Z" form of v (leading "v"
// stripped, missing patch filled in as 0), or false if v does not parse.
//
// The canonical form contains only digits and dots, so it is safe to embed in
// file names (staged-<ver>, apply-failed-<ver>, <ver>.zip): any spelling of
// the same version maps to the same name, and no input can inject a path
// separator.
func normalizeVersion(v string) (string, bool) {
	p, ok := parseSemver(v)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", p[0], p[1], p[2]), true
}

// sameVersion reports whether a and b denote the same version. It returns
// false if either side fails to parse, so "dev" or "" never matches anything
// (including itself).
func sameVersion(a, b string) bool {
	pa, okA := parseSemver(a)
	pb, okB := parseSemver(b)
	return okA && okB && pa == pb
}

// isNewer returns true if latest is a higher semver than current.
// Strips leading "v" from both. Returns false on any parse error.
func isNewer(latest, current string) bool {
	latestParts, ok1 := parseSemver(latest)
	currentParts, ok2 := parseSemver(current)
	if !ok1 || !ok2 {
		return false
	}

	for i := 0; i < 3; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return false
}

// parseSemver parses "v1.2.3" or "1.2.3" into [3]int{1, 2, 3}.
func parseSemver(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	// Release tags are two-component (v1.3) or three-component (v1.3.1);
	// a missing patch component counts as 0.
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [3]int{}, false
	}
	var result [3]int
	for i, p := range parts {
		// Strip any pre-release suffix (e.g., "3-rc1")
		if idx := strings.IndexAny(p, "-+"); idx >= 0 {
			p = p[:idx]
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		result[i] = n
	}
	return result, true
}
