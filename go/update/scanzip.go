package update

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// maxUncompressedBytes caps the sum of declared uncompressed entry sizes in a
// downloaded archive. A var so tests can lower it.
var maxUncompressedBytes uint64 = 300 << 20

// maxZipEntries caps the number of entries; the real bundle has a handful,
// and each entry costs an inode before verification can reject the bundle.
// A var so tests can lower it.
var maxZipEntries = 10000

// Rejection reasons shared by scanZip and extractZip.
var (
	errArchiveTooLarge  = errors.New("update archive is too large")
	errArchiveEntryType = errors.New("update archive entry is not a regular file or directory")
	errArchiveLayout    = errors.New("update archive layout is invalid")
)

// scanZip inspects the central directory of the archive at path, before any
// extraction, and returns the name of its single top-level "<name>.app"
// bundle directory (e.g. "RHG Authenticator.app").
//
// The archive is rejected if it is empty, if any entry name is not a clean
// relative slash-separated path (empty, absolute, backslash, "." or ".."
// segments, empty segments), if any entry is a symlink or other non-regular
// file, if entries are not all inside one top-level directory whose name ends
// in ".app" (so a top-level "__MACOSX/" or "._x" entry is rejected), or if the
// declared uncompressed sizes sum to more than maxUncompressedBytes, or if it
// has more than maxZipEntries entries.
//
// Declared sizes are only a pre-filter: the extractor must still enforce the
// cap on bytes actually written, since a crafted header can understate them.
func scanZip(path string) (string, error) {
	r, err := openArchive(path)
	if err != nil {
		return "", err
	}
	defer r.Close()

	if len(r.File) == 0 {
		return "", errors.New("update archive is empty")
	}
	if len(r.File) > maxZipEntries {
		return "", fmt.Errorf("%w: more than %d entries", errArchiveTooLarge, maxZipEntries)
	}

	var top string
	var total uint64
	// Colliding names would only fail later, at extraction, as local-looking
	// EEXIST/ENOTDIR errors; reject them here so they count as a bad release.
	seen := make(map[string]bool)  // every entry path
	files := make(map[string]bool) // regular-file entry paths
	dirs := make(map[string]bool)  // paths used as a parent of another entry
	for _, f := range r.File {
		segs, err := zipEntrySegments(f.Name)
		if err != nil {
			return "", err
		}

		mode := f.Mode()
		if mode&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("update archive entry %q is a symlink", f.Name)
		}
		if t := mode.Type(); t != 0 && t != fs.ModeDir {
			return "", fmt.Errorf("%w: %q", errArchiveEntryType, f.Name)
		}

		if top == "" {
			top = segs[0]
			if !isAppBundleName(top) {
				return "", fmt.Errorf("update archive top-level entry %q is not an .app bundle", top)
			}
		} else if segs[0] != top {
			return "", fmt.Errorf("update archive has more than one top-level entry (%q, %q)", top, segs[0])
		}
		// The bundle itself must be a directory, never a file named "X.app".
		if len(segs) == 1 && !mode.IsDir() {
			return "", fmt.Errorf("update archive top-level entry %q is not a directory", f.Name)
		}

		p := strings.Join(segs, "/")
		if seen[p] {
			return "", fmt.Errorf("%w: duplicate entry %q", errArchiveLayout, f.Name)
		}
		seen[p] = true
		for k := 1; k < len(segs); k++ {
			parent := strings.Join(segs[:k], "/")
			if files[parent] {
				return "", fmt.Errorf("%w: %q is both a file and a directory", errArchiveLayout, parent)
			}
			dirs[parent] = true
		}
		if !mode.IsDir() {
			if dirs[p] {
				return "", fmt.Errorf("%w: %q is both a file and a directory", errArchiveLayout, p)
			}
			files[p] = true
		}

		if f.UncompressedSize64 > maxUncompressedBytes-total {
			return "", fmt.Errorf("%w: expands to more than %d bytes", errArchiveTooLarge, maxUncompressedBytes)
		}
		total += f.UncompressedSize64
	}
	return top, nil
}

// zipEntrySegments validates a zip entry name and splits it into path
// segments. Zip names always use "/" regardless of the creating OS; a single
// trailing "/" marks a directory entry. The check is OS-agnostic so the
// result is identical on every platform, with filepath.IsLocal as an extra
// guard against platform-specific forms (e.g. reserved names on Windows).
func zipEntrySegments(name string) ([]string, error) {
	invalid := fmt.Errorf("update archive entry name %q is not a safe relative path", name)
	trimmed := strings.TrimSuffix(name, "/")
	// ".." anywhere (not just as a whole segment) is rejected too: it is the
	// guard CodeQL's zip-slip query recognizes, and no real bundle needs it.
	if trimmed == "" || strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, "..") ||
		strings.ContainsFunc(trimmed, func(r rune) bool { return r == '\\' || r < 0x20 || r == 0x7f }) {
		return nil, invalid
	}
	segs := strings.Split(trimmed, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, invalid
		}
	}
	if !filepath.IsLocal(filepath.FromSlash(trimmed)) {
		return nil, invalid
	}
	return segs, nil
}

// isAppBundleName reports whether name looks like a macOS bundle directory:
// ends in ".app", has a non-empty stem, and is not hidden (no "._x.app"
// AppleDouble or dot-file names).
func isAppBundleName(name string) bool {
	return strings.HasSuffix(name, ".app") && len(name) > len(".app") &&
		!strings.HasPrefix(name, ".")
}

// openArchive opens the zip at path. zip.OpenReader can return a non-nil
// reader together with an error (e.g. zip.ErrInsecurePath), so close it then.
func openArchive(path string) (*zip.ReadCloser, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		if r != nil {
			r.Close()
		}
		return nil, fmt.Errorf("open update archive: %w", err)
	}
	return r, nil
}
