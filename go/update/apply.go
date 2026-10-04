package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errApplyGuard marks an apply refused by the pre-swap guard because the
// on-disk state does not describe a pending upgrade (e.g. the swap already
// happened). Nothing is wrong with the release, so no apply-failed marker is
// written.
var errApplyGuard = errors.New("update not applicable")

// applyDeps are apply's and readyStaged's OS operations, injectable for tests.
type applyDeps struct {
	bundleVersion func(bundlePath string) (string, error)
	verify        verifier
	swap          func(staged, current string) error
}

// defaultApplyDeps returns the production operations, verifying against
// PinnedRequirement.
func defaultApplyDeps() applyDeps {
	return applyDeps{
		bundleVersion: bundleVersion,
		verify:        pinnedVerifier(PinnedRequirement),
		swap:          swapBundles,
	}
}

// apply atomically exchanges sb.App (a verified bundle from stage or
// readyStaged) with currentBundle, the running app at version running.
//
// Pre-swap guard, all of which must hold:
//   - currentBundle's plist version equals running;
//   - sb.App's plist version equals sb.Version — after a swap the staged dir
//     holds the OLD bundle, so this stops a second apply from reversing the
//     update;
//   - sb.Version is newer than running;
//   - sb.App re-verifies (it may have sat on disk since it was staged).
//
// Marker policy: a verify failure, an unreadable staged plist, or a swap
// failure writes apply-failed-<sb.Version> under root, so that version is
// offered only as a manual update from then on — unless the cause wraps
// errTransient (a tool timed out, was killed, or could not run), which is
// retried on the next quit. The other guard failures describe a stale or
// already-applied state, not a bad release: they return an error wrapping
// errApplyGuard and write no marker (cleanup removes such dirs on the next
// launch), as does a staged bundle that has vanished since it was staged.
// On any error the current bundle is untouched. apply does not
// relaunch; the caller decides.
func apply(root string, sb stagedBundle, currentBundle, running string, d applyDeps) error {
	cur, err := d.bundleVersion(currentBundle)
	if err != nil {
		return fmt.Errorf("apply update: %w: current bundle: %w", errApplyGuard, err)
	}
	if !sameVersion(cur, running) {
		return fmt.Errorf("apply update: %w: current bundle is %q, running %q", errApplyGuard, cur, running)
	}

	// The staged bundle was verified when staged; if it has since vanished
	// (user cleared Application Support, another instance's cleanup), that is
	// local state, not a bad release, so no marker.
	if _, err := os.Lstat(sb.App); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("apply update: %w: staged bundle missing", errApplyGuard)
	} else if err != nil {
		return fmt.Errorf("apply update: %w: %w", errTransient, err)
	}
	staged, err := d.bundleVersion(sb.App)
	if err != nil {
		return failApply(root, sb.Version, err)
	}
	if !sameVersion(staged, sb.Version) {
		return fmt.Errorf("apply update: %w: staged bundle is %q, expected %q", errApplyGuard, staged, sb.Version)
	}
	if !isNewer(staged, running) {
		return fmt.Errorf("apply update: %w: staged %q is not newer than running %q", errApplyGuard, staged, running)
	}

	if err := d.verify(sb.App, sb.Version); err != nil {
		return failApply(root, sb.Version, err)
	}
	if err := d.swap(sb.App, currentBundle); err != nil {
		return failApply(root, sb.Version, fmt.Errorf("swap bundles: %w", err))
	}
	return nil
}

// failApply records an apply-failed marker for version (unless cause is
// errTransient) and returns cause, joined with any marker-write error.
func failApply(root, version string, cause error) error {
	err := fmt.Errorf("apply update %s: %w", version, cause)
	if errors.Is(cause, errTransient) {
		return err
	}
	if mErr := markApplyFailed(root, version); mErr != nil {
		return errors.Join(err, mErr)
	}
	return err
}

// readyStaged re-checks a staged bundle kept by cleanup: sb.Dir must contain
// exactly one entry, a real "<name>.app" directory, whose plist version
// equals sb.Version and which re-verifies. It returns sb with App set, or an
// error saying why the staged update is unusable. It never removes anything;
// on error the caller logs the reason and removes sb.Dir.
func readyStaged(sb stagedBundle, d applyDeps) (stagedBundle, error) {
	entries, err := os.ReadDir(sb.Dir)
	if err != nil {
		return stagedBundle{}, fmt.Errorf("staged update %s: %w", sb.Version, err)
	}
	if len(entries) != 1 || !entries[0].IsDir() || !isAppBundleName(entries[0].Name()) {
		return stagedBundle{}, fmt.Errorf("staged update %s: directory does not hold exactly one .app bundle", sb.Version)
	}
	app := filepath.Join(sb.Dir, entries[0].Name())
	v, err := d.bundleVersion(app)
	if err != nil {
		return stagedBundle{}, fmt.Errorf("staged update %s: %w", sb.Version, err)
	}
	if !sameVersion(v, sb.Version) {
		return stagedBundle{}, fmt.Errorf("staged update %s: bundle is %q", sb.Version, v)
	}
	if err := d.verify(app, sb.Version); err != nil {
		return stagedBundle{}, fmt.Errorf("staged update %s: %w", sb.Version, err)
	}
	sb.App = app
	return sb, nil
}

// relaunchCommand returns the launcher invocation that starts a new
// instance of the app at bundle without waiting for it.
func relaunchCommand(bundle string) (name string, args []string) {
	return openPath, []string{"-n", bundle}
}

// openPath is the system launcher used to relaunch the app.
const openPath = "/usr/bin/open"
