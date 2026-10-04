package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Staging layout. All updater state lives under one root, <dataDir>/update/:
//
//	<ver>.zip, <ver>.zip.partial   downloaded archive (transient)
//	staged-<ver>.tmp/              extraction in progress (transient)
//	staged-<ver>/                  verified bundle awaiting apply
//	apply-failed-<ver>             marker: applying <ver> failed; manual only
//	last-version                   version that ran last (see readLastVersion)
//	last-version.*.tmp             interrupted last-version write (transient)
//
// <ver> is always the canonical form from normalizeVersion when written by
// this package; cleanup also accepts any spelling parseSemver understands.
const (
	stagingDirName      = "update"
	stagedPrefix        = "staged-"
	tmpSuffix           = ".tmp"
	zipSuffix           = ".zip"
	partialSuffix       = ".partial"
	applyFailedPrefix   = "apply-failed-"
	lastVersionFileName = "last-version"
)

// maxLastVersionBytes bounds how much of the last-version file is read.
const maxLastVersionBytes = 256

// stagingRoot returns the staging root for dataDir.
func stagingRoot(dataDir string) string {
	return filepath.Join(dataDir, stagingDirName)
}

// stagedDirPath returns <root>/staged-<X.Y.Z> for version, or false if
// version does not parse.
func stagedDirPath(root, version string) (string, bool) {
	ver, ok := normalizeVersion(version)
	if !ok {
		return "", false
	}
	return filepath.Join(root, stagedPrefix+ver), true
}

// stagedBundle is one staged-<ver>/ directory. Every function that produces
// or consumes a staged update passes this value, so the directory, the
// bundle inside it and the version its name promises can never be mixed up.
type stagedBundle struct {
	Dir     string // the staged-<ver> directory
	App     string // the .app inside Dir; "" until verified (stage, readyStaged)
	Version string // canonical "X.Y.Z" from Dir's name
}

// cleanupResult reports what cleanup kept.
type cleanupResult struct {
	// Staged is the highest staged bundle newer than the running version
	// without an apply-failed marker, or nil if there is none. It has not
	// been re-verified: pass it to readyStaged before applying.
	Staged *stagedBundle
	// ApplyFailed lists canonical versions (newer than running) with an
	// apply-failed marker; the caller should offer those as manual-only.
	ApplyFailed []string
}

// cleanup prunes the staging root at startup, given the running version.
//
// It removes: staged-*.tmp entries; *.zip and *.zip.partial files; orphaned
// last-version temp files from an interrupted writeLastVersion;
// staged-<ver> entries whose version is <= running, unparsable, not a real
// directory (e.g. a symlink), or superseded by a higher staged version; and
// apply-failed-<ver> markers whose version is <= running or unparsable; and a
// staged bundle whose version has an apply-failed marker (applying it already
// failed, so retrying on every quit would only fail again).
// Anything else (e.g. last-version) is left alone.
//
// If running does not parse (e.g. "dev"), no version counts as newer, so every
// staged bundle and marker is removed.
//
// A missing root is not an error. Removal failures do not stop the scan; they
// are joined into the returned error alongside the (still valid) result.
func cleanup(root, running string) (cleanupResult, error) {
	var res cleanupResult
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("read staging root: %w", err)
	}

	var errs []error
	remove := func(name string) {
		if err := os.RemoveAll(filepath.Join(root, name)); err != nil {
			errs = append(errs, err)
		}
	}

	var best string // entry name of the best staged candidate so far
	var bestVer string
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, stagedPrefix) && strings.HasSuffix(name, tmpSuffix),
			strings.HasSuffix(name, zipSuffix),
			strings.HasSuffix(name, zipSuffix+partialSuffix),
			strings.HasPrefix(name, lastVersionFileName+".") && strings.HasSuffix(name, tmpSuffix):
			remove(name)

		case strings.HasPrefix(name, stagedPrefix):
			ver, ok := newerVersion(strings.TrimPrefix(name, stagedPrefix), running)
			if !ok || !e.Type().IsDir() {
				remove(name)
				continue
			}
			if best == "" {
				best, bestVer = name, ver
				continue
			}
			if isNewer(ver, bestVer) {
				remove(best)
				best, bestVer = name, ver
			} else {
				remove(name)
			}

		case strings.HasPrefix(name, applyFailedPrefix):
			ver, ok := newerVersion(strings.TrimPrefix(name, applyFailedPrefix), running)
			if !ok {
				remove(name)
				continue
			}
			res.ApplyFailed = append(res.ApplyFailed, ver)
		}
	}

	if best != "" {
		if slices.Contains(res.ApplyFailed, bestVer) {
			remove(best)
		} else {
			res.Staged = &stagedBundle{Dir: filepath.Join(root, best), Version: bestVer}
		}
	}
	return res, errors.Join(errs...)
}

// newerVersion returns the canonical form of v if v parses and is strictly
// newer than running.
func newerVersion(v, running string) (string, bool) {
	canon, ok := normalizeVersion(v)
	if !ok || !isNewer(canon, running) {
		return "", false
	}
	return canon, true
}

// applyFailedPath returns the marker path for version, or false if version
// does not parse.
func applyFailedPath(root, version string) (string, bool) {
	ver, ok := normalizeVersion(version)
	if !ok {
		return "", false
	}
	return filepath.Join(root, applyFailedPrefix+ver), true
}

// markApplyFailed records that applying version failed, so it is offered
// only as a manual update from now on. Creates root (0o700) if missing.
func markApplyFailed(root, version string) error {
	p, ok := applyFailedPath(root, version)
	if !ok {
		return fmt.Errorf("invalid version %q", version)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create staging root: %w", err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return fmt.Errorf("write apply-failed marker: %w", err)
	}
	return nil
}

// isApplyFailed reports whether an apply-failed marker exists for version.
// An unparsable version has no marker and returns false.
func isApplyFailed(root, version string) bool {
	p, ok := applyFailedPath(root, version)
	if !ok {
		return false
	}
	_, err := os.Lstat(p)
	return err == nil
}

// shouldShowUpdatedBanner reports whether to tell the user the app was just
// updated: only when a last-version file existed and its stored version is
// strictly older than running. A missing file (first run), an equal version,
// a downgrade, or an unparsable value on either side all return false.
func shouldShowUpdatedBanner(stored string, exists bool, running string) bool {
	return exists && isNewer(running, stored)
}

// lastVersionPath returns <dataDir>/update/last-version.
func lastVersionPath(dataDir string) string {
	return filepath.Join(stagingRoot(dataDir), lastVersionFileName)
}

// readLastVersion returns the trimmed contents of <dataDir>/update/last-version
// and whether the file could be read. Any read error (including not-exist)
// returns ("", false). At most maxLastVersionBytes are read.
func readLastVersion(dataDir string) (string, bool) {
	f, err := os.Open(lastVersionPath(dataDir))
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLastVersionBytes))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// writeLastVersion atomically records v as the last-run version in
// <dataDir>/update/last-version (0o600), creating the directory (0o700) if
// missing.
func writeLastVersion(dataDir, v string) error {
	root := stagingRoot(dataDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create staging root: %w", err)
	}
	tmp, err := os.CreateTemp(root, lastVersionFileName+".*"+tmpSuffix)
	if err != nil {
		return fmt.Errorf("write last-version: %w", err)
	}
	tmpPath := tmp.Name()
	_, werr := tmp.WriteString(v + "\n")
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write last-version: %w", err)
	}
	if err := os.Rename(tmpPath, lastVersionPath(dataDir)); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write last-version: %w", err)
	}
	return nil
}
