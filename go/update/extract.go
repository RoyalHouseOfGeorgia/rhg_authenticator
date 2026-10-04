package update

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// extractZip extracts the archive at zipPath into destDir, which must already
// exist and should be a fresh private directory.
//
// Precondition: scanZip accepted the archive. Entry names and types are
// re-validated here anyway (cheap, and the file could change in between), so
// every target path is local to destDir. Directories are created 0o755;
// regular files get the entry's permission bits (preserving the exec bit on
// Contents/MacOS/<bin>) and are opened O_CREATE|O_EXCL (plus O_NOFOLLOW where
// available), so no pre-existing path — symlink, file or duplicate entry — is
// ever written through. No symlinks are created.
//
// The bytes actually written across all entries are capped at
// maxUncompressedBytes, independently of the declared sizes scanZip checked;
// archive/zip additionally fails an entry whose content exceeds its declared
// size. On error, partially extracted content is left for the caller to
// remove.
func extractZip(zipPath, destDir string) error {
	r, err := openArchive(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	remaining := maxUncompressedBytes
	for _, f := range r.File {
		if _, err := zipEntrySegments(f.Name); err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))
		mode := f.Mode()
		switch mode.Type() {
		case fs.ModeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("extract %q: %w", f.Name, err)
			}
		case 0:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("extract %q: %w", f.Name, err)
			}
			n, err := extractFile(f, target, remaining)
			if err != nil {
				return err
			}
			remaining -= n
		default:
			return fmt.Errorf("%w: %q", errArchiveEntryType, f.Name)
		}
	}
	return nil
}

// extractFile writes entry f to a new file at target, failing if more than
// limit bytes would be written. Returns the number of bytes written.
func extractFile(f *zip.File, target string, limit uint64) (uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, fmt.Errorf("extract %q: %w", f.Name, err)
	}
	defer rc.Close()

	// codesign seals contents, not modes, so the archive's mode bits are
	// untrusted: keep only "executable or not", never group/other write.
	perm := os.FileMode(0o644)
	if f.Mode().Perm()&0o111 != 0 {
		perm = 0o755
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, perm)
	if err != nil {
		return 0, fmt.Errorf("extract %q: %w", f.Name, err)
	}
	// Read one byte past the limit so an over-cap entry is detected rather
	// than silently truncated.
	n, copyErr := io.Copy(out, io.LimitReader(rc, int64(limit)+1))
	// The umask may have stripped bits at creation; set the clamped mode exactly.
	chmodErr := out.Chmod(perm)
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		return 0, fmt.Errorf("extract %q: %w", f.Name, copyErr)
	case uint64(n) > limit:
		return 0, fmt.Errorf("%w: expands to more than %d bytes", errArchiveTooLarge, maxUncompressedBytes)
	case chmodErr != nil:
		return 0, fmt.Errorf("extract %q: %w", f.Name, chmodErr)
	case closeErr != nil:
		return 0, fmt.Errorf("extract %q: %w", f.Name, closeErr)
	}
	return uint64(n), nil
}
