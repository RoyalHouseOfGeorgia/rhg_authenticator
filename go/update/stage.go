package update

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// errBundleRejected marks a release that failed for a reason that will not
// change on retry: the archive failed the pre-scan, its contents broke the
// extraction rules, or the bundle failed verification. The caller records an
// apply-failed marker so the release is not downloaded again every check.
// Local failures (opening the zip, disk full, I/O errors, errTransient from a
// tool) are not wrapped.
var errBundleRejected = errors.New("update rejected")

// stage extracts the update archive at zipPath and verifies it for version,
// leaving the verified bundle in <root>/staged-<X.Y.Z>/ and returning it.
//
// Steps: scanZip → fresh staged-<X.Y.Z>.tmp (any stale one is removed first)
// → extractZip → verify(bundle, version) → rename the tmp dir into place. On
// any failure the tmp dir is removed and nothing is staged. The staged dir
// must not already exist (readyStaged it, or let cleanup remove it).
//
// stage never deletes or modifies zipPath: the caller owns it (the Manager
// deletes it; the read-only --verify-update-zip CLI must leave it intact).
func stage(zipPath, root, version string, verify verifier) (stagedBundle, error) {
	dir, ok := stagedDirPath(root, version)
	if !ok {
		return stagedBundle{}, fmt.Errorf("stage update: invalid version %q", version)
	}
	appName, err := scanZip(zipPath)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) { // the local file could not be read
			return stagedBundle{}, fmt.Errorf("stage update: %w", err)
		}
		return stagedBundle{}, fmt.Errorf("stage update: %w: %w", errBundleRejected, err)
	}
	if _, err := os.Lstat(dir); err == nil {
		return stagedBundle{}, fmt.Errorf("stage update: %s already exists", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return stagedBundle{}, fmt.Errorf("stage update: %w", err)
	}

	tmp := dir + tmpSuffix
	if err := os.RemoveAll(tmp); err != nil {
		return stagedBundle{}, fmt.Errorf("stage update: remove stale extraction: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return stagedBundle{}, fmt.Errorf("stage update: %w", err)
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return stagedBundle{}, fmt.Errorf("stage update: %w", err)
	}

	if err := stageInto(zipPath, tmp, appName, version, verify); err != nil {
		os.RemoveAll(tmp)
		return stagedBundle{}, fmt.Errorf("stage update: %w", err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		return stagedBundle{}, fmt.Errorf("stage update: %w", err)
	}
	canon, _ := normalizeVersion(version)
	return stagedBundle{Dir: dir, App: filepath.Join(dir, appName), Version: canon}, nil
}

// stageInto extracts zipPath into tmp and verifies the bundle tmp/appName,
// wrapping permanent failures in errBundleRejected.
func stageInto(zipPath, tmp, appName, version string, verify verifier) error {
	if err := extractZip(zipPath, tmp); err != nil {
		if isArchiveRejection(err) {
			return fmt.Errorf("%w: %w", errBundleRejected, err)
		}
		return err
	}
	if err := verify(filepath.Join(tmp, appName), version); err != nil {
		if errors.Is(err, errTransient) {
			return err
		}
		return fmt.Errorf("%w: %w", errBundleRejected, err)
	}
	return nil
}

// isArchiveRejection reports whether an extraction error comes from the
// archive's contents rather than the local machine.
//
// stage extracts into a fresh, empty directory it just created, so EEXIST,
// ENOTDIR and ENAMETOOLONG can only come from the archive's own entry names
// (e.g. names that differ only in case or Unicode normalization, which APFS
// treats as the same file). Classifying by errno covers that whole class
// without re-implementing the file system's name rules in scanZip.
func isArchiveRejection(err error) bool {
	return errors.Is(err, errArchiveTooLarge) || errors.Is(err, errArchiveEntryType) ||
		errors.Is(err, errArchiveLayout) ||
		errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENAMETOOLONG) ||
		errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrChecksum) ||
		errors.Is(err, zip.ErrAlgorithm) || errors.Is(err, zip.ErrInsecurePath) ||
		errors.Is(err, io.ErrUnexpectedEOF) || // entry data shorter than its header claims
		errors.As(err, new(flate.CorruptInputError))
}
