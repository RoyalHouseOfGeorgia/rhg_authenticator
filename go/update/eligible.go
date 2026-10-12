package update

import (
	"path"
	"path/filepath"
	"strings"
)

// Reasons eligible reports when the running bundle cannot be updated in
// place. Short machine strings for logs and UI hints.
const (
	reasonNotBundle   = "not-bundle"
	reasonTranslocate = "translocated"
	reasonOutside     = "outside-applications"
	reasonNotWritable = "not-writable"
	reasonUnsupported = "unsupported-platform"
)

// bundleFromExecutable returns the .app bundle containing exe when exe has
// the layout <...>/<name>.app/Contents/MacOS/<bin>, or false otherwise.
// Paths are handled in slash form (macOS paths always are), so the result is
// the same on every platform the tests run on.
func bundleFromExecutable(exe string) (string, bool) {
	p := path.Clean(filepath.ToSlash(exe))
	if !path.IsAbs(p) {
		return "", false
	}
	macOS := path.Dir(p)
	contents := path.Dir(macOS)
	bundle := path.Dir(contents)
	if path.Base(macOS) != "MacOS" || path.Base(contents) != "Contents" ||
		!isAppBundleName(path.Base(bundle)) {
		return "", false
	}
	return bundle, true
}

// eligible reports whether bundle can be swapped in place: it must not be
// running from an App Translocation mount, its parent must be exactly
// /Applications or <home>/Applications (compared after cleaning, without
// resolving symlinks), and access(W_OK) must succeed on both the parent
// (rename into it) and the bundle itself (moving a directory rewrites its
// ".." entry). reason is "" when ok.
func eligible(bundle, home string, access func(path string) error) (ok bool, reason string) {
	b := path.Clean(filepath.ToSlash(bundle))
	if strings.Contains(b+"/", "/AppTranslocation/") {
		return false, reasonTranslocate
	}
	if !path.IsAbs(b) {
		return false, reasonOutside
	}
	parent := path.Dir(b)
	inApps := parent == "/Applications"
	if h := path.Clean(filepath.ToSlash(home)); home != "" && path.IsAbs(h) {
		inApps = inApps || parent == path.Join(h, "Applications")
	}
	if !inApps {
		return false, reasonOutside
	}
	if access(parent) != nil || access(b) != nil {
		return false, reasonNotWritable
	}
	return true, ""
}

// eligibleFromExe locates the bundle containing the executable exe and
// reports whether it can be updated in place (see eligible). reason is ""
// when ok.
func eligibleFromExe(exe, home string, access func(path string) error) (bundle string, ok bool, reason string) {
	bundle, isBundle := bundleFromExecutable(exe)
	if !isBundle {
		return "", false, reasonNotBundle
	}
	ok, reason = eligible(bundle, home, access)
	return bundle, ok, reason
}
