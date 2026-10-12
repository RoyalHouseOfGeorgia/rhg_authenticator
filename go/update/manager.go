package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// checkInterval is how often a running app re-checks for an update while no
// update is ready.
const checkInterval = 6 * time.Hour

// Manual-only reasons that are not eligibility reasons (see eligible.go).
const (
	reasonNoAsset     = "no-asset"
	reasonApplyFailed = "apply-failed" // rejected at stage or failed to apply
	reasonRetrying    = "retrying"     // failed again after an earlier temporary failure; still retried
)

// State is what the UI should offer for updates.
type State int

const (
	// StateIdle: nothing to show.
	StateIdle State = iota
	// StateReady: a verified update is staged; offer "Restart now".
	StateReady
	// StateManualOnly: a newer release exists but must be installed by hand;
	// offer a Download link.
	StateManualOnly
)

// Status is the Manager's externally visible state.
type Status struct {
	State State
	// Version is the canonical "X.Y.Z" (no "v") of the offered update; ""
	// when Idle.
	Version string
	// ReleaseURL is the release page for the Download link; "" when Idle.
	ReleaseURL string
	// MoveToApplications is set only in ManualOnly, when the app could update
	// itself if it were moved into an Applications folder (it is running
	// translocated or from elsewhere).
	MoveToApplications bool
}

// Config configures a Manager.
type Config struct {
	// DataDir is the app data dir; the staging root is stagingRoot(DataDir).
	DataDir string
	// Running is the running version (buildinfo.Version, e.g. "v1.5.0" or
	// "dev").
	Running string
	// Owner and Repo name the GitHub repository releases come from.
	Owner, Repo string
	// OnStatus is called from the Manager goroutine whenever the Status
	// changes (never for a repeat of the same Status). May be nil.
	OnStatus func(Status)
	// OnUpdated is called at most once, from Run, when the app was just
	// updated: version is the canonical running version and releaseURL its
	// release page. May be nil.
	OnUpdated func(version, releaseURL string)
	// Logf receives every "update: ..." log line. May be nil.
	Logf func(format string, args ...any)
}

// managerDeps are the Manager's operations, injectable for tests.
type managerDeps struct {
	check       func(owner, repo, current string) CheckResult
	eligible    func() (bundle string, ok bool, reason string)
	cleanup     func(root, running string) (cleanupResult, error)
	download    func(ctx context.Context, url, destDir, version string) (string, error)
	stage       func(zipPath, root, version string, verify verifier) (stagedBundle, error)
	verify      verifier // passed to stage
	readyStaged func(sb stagedBundle) (stagedBundle, error)
	apply       func(root string, sb stagedBundle, currentBundle, running string) error
	relaunch    func(bundle string) error
	// newTicker returns a channel that fires every d and a stop function.
	newTicker func(d time.Duration) (<-chan time.Time, func())
}

// defaultManagerDeps returns the production operations.
func defaultManagerDeps() managerDeps {
	ad := defaultApplyDeps() // the one place the pinned verifier is built
	return managerDeps{
		check:    Check,
		eligible: currentBundleEligible,
		cleanup:  cleanup,
		download: download,
		stage:    stage,
		verify:   ad.verify,
		readyStaged: func(sb stagedBundle) (stagedBundle, error) {
			return readyStaged(sb, ad)
		},
		apply: func(root string, sb stagedBundle, currentBundle, running string) error {
			return apply(root, sb, currentBundle, running, ad)
		},
		relaunch: relaunch,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
	}
}

// Manager runs the update lifecycle: startup cleanup, the "Updated to"
// notice, then a check at launch and every checkInterval until an update is
// Ready, downloading and staging it when the app can update itself. The
// update is applied only by ApplyIfReady, after the UI has exited.
//
// Errors are logged, never shown: the user only ever sees a Status.
type Manager struct {
	cfg  Config
	deps managerDeps
	root string

	// Owned by the Run goroutine.
	eligibleOK bool
	reason     string
	eligBundle string          // the running bundle, when eligibleOK
	kept       *stagedBundle   // staged bundle cleanup kept; settled by the first attempt
	failed     map[string]bool // versions rejected at stage or apply-failed; never retried
	lastFailed string          // version whose last download/stage failed temporarily

	mu      sync.Mutex
	status  Status
	ready   stagedBundle // the staged update to apply; valid when status.State == StateReady
	bundle  string       // copy of eligBundle for ApplyIfReady; valid when Ready
	applied bool         // ApplyIfReady already ran
}

// NewManager returns a Manager for cfg using the production operations.
func NewManager(cfg Config) *Manager {
	return newManager(cfg, defaultManagerDeps())
}

// newManager returns a Manager with injected operations.
func newManager(cfg Config, deps managerDeps) *Manager {
	return &Manager{
		cfg:    cfg,
		deps:   deps,
		root:   stagingRoot(cfg.DataDir),
		failed: map[string]bool{},
	}
}

// Run performs startup housekeeping and checks for updates at launch and on
// every tick while no update is Ready. It blocks until ctx is done; the
// caller runs it on its own goroutine (safego.Go).
//
// Once Ready, Run never touches the staging root again, so ApplyIfReady may
// be called after cancelling ctx without waiting for Run to return.
func (m *Manager) Run(ctx context.Context) {
	m.startup()
	if ctx.Err() != nil {
		return
	}
	m.attempt(ctx)

	tick, stop := m.deps.newTicker(checkInterval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if m.currentStatus().State == StateReady {
				continue
			}
			m.attempt(ctx)
		}
	}
}

// currentStatus returns the current Status.
func (m *Manager) currentStatus() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// ApplyIfReady installs the Ready update over the running bundle and, if
// relaunch is set, starts the app again — the new version, or the unchanged
// old one if the install failed (the user asked for a restart; the old app
// offers the update again, or as a Download if apply marked it failed). It
// does nothing unless an update is Ready, and applies at most once. Call it
// on the main goroutine after the UI has exited, as the last thing before
// exit.
func (m *Manager) ApplyIfReady(relaunch bool) {
	m.mu.Lock()
	if m.status.State != StateReady || m.applied {
		m.mu.Unlock()
		return
	}
	m.applied = true
	sb, bundle := m.ready, m.bundle
	m.mu.Unlock()

	// apply writes its own apply-failed marker when the release is at fault.
	// On error apply leaves the current bundle untouched. The logged
	// duration is the install (re-verify + swap), the bulk of the delay
	// before a relaunch.
	start := time.Now()
	err := m.deps.apply(m.root, sb, bundle, m.cfg.Running)
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		m.logf("update: apply v%s failed after %s: %s", sb.Version, took, sanitizeErr(err))
	} else {
		m.logf("update: applied v%s in %s", sb.Version, took)
	}
	if relaunch {
		if err := m.deps.relaunch(bundle); err != nil {
			m.logf("update: relaunch: %s", sanitizeErr(err))
		}
	}
}

// startup prunes the staging root, shows the "Updated to" notice when the
// running version is newer than the last one recorded, records the running
// version, and determines eligibility. It makes no network calls.
func (m *Manager) startup() {
	res, err := m.deps.cleanup(m.root, m.cfg.Running)
	if err != nil {
		m.logf("update: cleanup: %s", sanitizeErr(err))
	}
	m.kept = res.Staged
	for _, v := range res.ApplyFailed {
		m.failed[v] = true
	}

	stored, exists := readLastVersion(m.cfg.DataDir)
	if running, ok := normalizeVersion(m.cfg.Running); ok {
		if shouldShowUpdatedBanner(stored, exists, m.cfg.Running) && m.cfg.OnUpdated != nil {
			m.cfg.OnUpdated(running, m.releasePage(running))
		}
		if err := writeLastVersion(m.cfg.DataDir, m.cfg.Running); err != nil {
			m.logf("update: %s", sanitizeErr(err))
		}
	}

	m.eligBundle, m.eligibleOK, m.reason = m.deps.eligible()
	if !m.eligibleOK {
		m.logf("update: not eligible for in-app update: %s", m.reason)
	}
}

// attempt runs one check and moves to Ready or ManualOnly as appropriate.
// A download or local staging failure is retried on every tick; the first
// one is only logged, a repeat also offers the release as a Download.
func (m *Manager) attempt(ctx context.Context) {
	res := m.deps.check(m.cfg.Owner, m.cfg.Repo, m.cfg.Running)
	if res.LatestVersion == "" {
		m.logf("update: check failed or no eligible release")
		// Offline, or no usable latest release: a staged bundle from an
		// earlier run (re-verified against the pin) can still be offered.
		if kept := m.takeKept(); kept != nil {
			m.reuseStaged(*kept, m.releasePage(kept.Version))
		}
		return
	}

	var ver, reason string
	if res.UpdateAvailable {
		var ok bool
		if ver, ok = normalizeVersion(res.LatestVersion); !ok {
			m.logf("update: invalid release version")
			return
		}
		switch {
		case !m.eligibleOK:
			reason = m.reason
		case res.AssetURL == "":
			reason = reasonNoAsset
		case m.failed[ver] || isApplyFailed(m.root, ver):
			reason = reasonApplyFailed
		}
	}

	// The check reached GitHub: the kept staged bundle is usable only if it
	// is the latest release and installable; otherwise never offer it.
	kept := m.takeKept()
	if kept != nil && (reason != "" || kept.Version != ver) {
		m.logf("update: removing superseded staged %s", kept.Version)
		m.removeStaged(*kept)
		kept = nil
	}

	if kept != nil && m.reuseStaged(*kept, res.DownloadURL) {
		return
	}
	switch {
	case !res.UpdateAvailable:
		m.logf("update: up to date")
		m.setStatus(Status{State: StateIdle})
	case reason != "":
		m.setManualOnly(ver, res.DownloadURL, reason)
	default:
		m.downloadAndStage(ctx, ver, res)
	}
}

// downloadAndStage fetches and stages ver, moving to Ready on success. A
// rejected release is marked apply-failed and offered as manual only; other
// failures go through retryLater.
func (m *Manager) downloadAndStage(ctx context.Context, ver string, res CheckResult) {
	// stage requires a fresh staged dir; a leftover would fail every retry.
	if dir, ok := stagedDirPath(m.root, ver); ok {
		if err := os.RemoveAll(dir); err != nil {
			m.logf("update: remove leftover staged %s: %s", ver, sanitizeErr(err))
			m.retryLater(ver, res.DownloadURL)
			return
		}
	}
	zipPath, err := m.deps.download(ctx, res.AssetURL, m.root, ver)
	if err != nil {
		if ctx.Err() == nil {
			m.logf("update: download v%s failed: %s", ver, sanitizeErr(err))
			m.retryLater(ver, res.DownloadURL)
		}
		return
	}
	sb, err := m.deps.stage(zipPath, m.root, ver, m.deps.verify)
	// The Manager owns the zip: stage never deletes its input.
	if rmErr := os.Remove(zipPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		m.logf("update: remove download: %s", sanitizeErr(rmErr))
	}
	if err != nil {
		m.logf("update: stage v%s failed: %s", ver, sanitizeErr(err))
		if !errors.Is(err, errBundleRejected) {
			m.retryLater(ver, res.DownloadURL)
			return
		}
		m.failed[ver] = true
		if mErr := markApplyFailed(m.root, ver); mErr != nil {
			m.logf("update: %s", sanitizeErr(mErr))
		}
		m.setManualOnly(ver, res.DownloadURL, reasonApplyFailed)
		return
	}
	m.setReady(sb, res.DownloadURL)
}

// retryLater records a temporary failure for ver; the next tick retries. A
// one-off failure shows nothing, but a repeat offers the release as a
// Download so a persistent problem (blocked download host, unwritable
// staging root) never hides the update.
//
// Earlier failures are remembered across launches (download-failed-<ver>),
// since most sessions end before the first tick. A Download banner already
// showing for an older release is switched to ver at once.
func (m *Manager) retryLater(ver, releaseURL string) {
	marker := filepath.Join(m.root, downloadFailedPrefix+ver)
	_, statErr := os.Lstat(marker)
	cur := m.currentStatus()
	if m.lastFailed == ver || statErr == nil || (cur.State == StateManualOnly && cur.Version != ver) {
		m.setManualOnly(ver, releaseURL, reasonRetrying)
	}
	m.lastFailed = ver
	if statErr == nil {
		return
	}
	err := os.MkdirAll(m.root, 0o700)
	if err == nil {
		err = os.WriteFile(marker, nil, 0o600)
	}
	if err != nil {
		m.logf("update: record download failure: %s", sanitizeErr(err))
	}
}

// takeKept returns the staged bundle cleanup kept, if the app is eligible,
// and forgets it so it is considered only once. When the app is ineligible
// the bundle is left on disk for a later launch.
func (m *Manager) takeKept() *stagedBundle {
	kept := m.kept
	m.kept = nil
	if !m.eligibleOK {
		return nil
	}
	return kept
}

// reuseStaged re-verifies a staged bundle and moves to Ready. On failure it
// logs why, removes the staged dir, and returns false.
func (m *Manager) reuseStaged(sb stagedBundle, releaseURL string) bool {
	ready, err := m.deps.readyStaged(sb)
	if err != nil {
		m.logf("update: discarded staged %s: %s", sb.Version, sanitizeErr(err))
		m.removeStaged(sb)
		return false
	}
	m.setReady(ready, releaseURL)
	return true
}

// removeStaged deletes a staged dir, logging any failure.
func (m *Manager) removeStaged(sb stagedBundle) {
	if err := os.RemoveAll(sb.Dir); err != nil {
		m.logf("update: remove staged %s: %s", sb.Version, sanitizeErr(err))
	}
}

// setReady records sb as the update to apply and moves to Ready.
func (m *Manager) setReady(sb stagedBundle, releaseURL string) {
	m.logf("update: ready v%s", sb.Version)
	if err := os.Remove(filepath.Join(m.root, downloadFailedPrefix+sb.Version)); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.logf("update: %s", sanitizeErr(err))
	}
	m.mu.Lock()
	m.ready, m.bundle = sb, m.eligBundle
	m.mu.Unlock()
	m.setStatus(Status{State: StateReady, Version: sb.Version, ReleaseURL: releaseURL})
}

// setManualOnly moves to ManualOnly for ver.
func (m *Manager) setManualOnly(ver, releaseURL, reason string) {
	m.logf("update: manual only v%s (%s)", ver, reason)
	m.setStatus(Status{
		State:              StateManualOnly,
		Version:            ver,
		ReleaseURL:         releaseURL,
		MoveToApplications: reason == reasonTranslocate || reason == reasonOutside,
	})
}

// setStatus stores s and notifies OnStatus if it differs from the current
// Status. The callback runs without the lock held.
func (m *Manager) setStatus(s Status) {
	m.mu.Lock()
	if m.status == s {
		m.mu.Unlock()
		return
	}
	m.status = s
	m.mu.Unlock()
	if m.cfg.OnStatus != nil {
		m.cfg.OnStatus(s)
	}
}

// releasePage returns the GitHub release page for canonical version ver.
func (m *Manager) releasePage(ver string) string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/tag/v%s", m.cfg.Owner, m.cfg.Repo, ver)
}

func (m *Manager) logf(format string, args ...any) {
	if m.cfg.Logf != nil {
		m.cfg.Logf(format, args...)
	}
}

// sanitizeErr renders err for a log line.
func sanitizeErr(err error) string {
	return core.SanitizeForLog(err.Error())
}
