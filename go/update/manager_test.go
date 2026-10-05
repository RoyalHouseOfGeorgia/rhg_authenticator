package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testReleaseURL    = "https://github.com/o/r/releases/tag/v1.5.1"
	testAssetURL      = "https://github.com/o/r/releases/download/v1.5.1/" + darwinAssetName
	testRunningBundle = "/Applications/RHG Authenticator.app"
)

// fakeEnv holds the fake dependencies of a Manager and records every call.
// Fields are read by the test only after Run has returned (or without Run).
type fakeEnv struct {
	t       *testing.T
	dataDir string
	root    string
	running string

	mu       sync.Mutex
	logs     []string
	statuses []Status
	updated  [][2]string

	checks     []CheckResult // consumed in order; the last one repeats
	checkCalls int

	eligBundle string
	eligOK     bool
	reason     string

	cleanupRes cleanupResult
	cleanupErr error

	downloadErr   error
	downloadCalls int
	downloadDir   bool // return a non-empty directory instead of a zip file
	zips          []string

	stageErrs         []error // consumed in order; nil (or exhausted) succeeds
	stageCalls        int
	zipExistedAtStage bool

	readyErr   error
	readyCalls int

	applyErr      error
	applyCalls    int
	appliedSB     stagedBundle
	appliedBundle string

	relaunchErr   error
	relaunchCalls []string

	tick    chan time.Time
	started chan struct{} // closed when Run creates its ticker (first attempt done)
	stopped bool
}

// newFakeEnv returns an eligible environment whose check offers v1.5.1 with
// a macOS asset over a running v1.5.0.
func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	dataDir := t.TempDir()
	return &fakeEnv{
		t:          t,
		dataDir:    dataDir,
		root:       stagingRoot(dataDir),
		running:    "v1.5.0",
		checks:     []CheckResult{available("v1.5.1", true)},
		eligBundle: testRunningBundle,
		eligOK:     true,
		tick:       make(chan time.Time),
		started:    make(chan struct{}),
	}
}

// available returns a CheckResult offering ver, with the macOS asset if asset.
func available(ver string, asset bool) CheckResult {
	res := CheckResult{UpdateAvailable: true, LatestVersion: ver, DownloadURL: testReleaseURL, CurrentVersion: "v1.5.0"}
	if asset {
		res.AssetURL = testAssetURL
	}
	return res
}

func (e *fakeEnv) config() Config {
	return Config{
		DataDir: e.dataDir,
		Running: e.running,
		Owner:   "o",
		Repo:    "r",
		OnStatus: func(s Status) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.statuses = append(e.statuses, s)
		},
		OnUpdated: func(v, u string) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.updated = append(e.updated, [2]string{v, u})
		},
		Logf: func(format string, args ...any) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.logs = append(e.logs, fmt.Sprintf(format, args...))
		},
	}
}

func (e *fakeEnv) deps() managerDeps {
	return managerDeps{
		check: func(owner, repo, current string) CheckResult {
			if owner != "o" || repo != "r" || current != e.running {
				e.t.Errorf("check(%q, %q, %q)", owner, repo, current)
			}
			i := min(e.checkCalls, len(e.checks)-1)
			e.checkCalls++
			return e.checks[i]
		},
		eligible: func() (string, bool, string) { return e.eligBundle, e.eligOK, e.reason },
		cleanup: func(root, running string) (cleanupResult, error) {
			if root != e.root || running != e.running {
				e.t.Errorf("cleanup(%q, %q)", root, running)
			}
			return e.cleanupRes, e.cleanupErr
		},
		download: func(_ context.Context, url, destDir, version string) (string, error) {
			e.downloadCalls++
			if url != testAssetURL || destDir != e.root {
				e.t.Errorf("download(%q, %q)", url, destDir)
			}
			if e.downloadErr != nil {
				return "", e.downloadErr
			}
			p := filepath.Join(destDir, version+zipSuffix)
			if err := os.MkdirAll(destDir, 0o700); err != nil {
				e.t.Fatal(err)
			}
			if e.downloadDir {
				populate(e.t, destDir, []string{version + zipSuffix}, nil)
			} else if err := os.WriteFile(p, []byte("zip"), 0o600); err != nil {
				e.t.Fatal(err)
			}
			e.zips = append(e.zips, p)
			return p, nil
		},
		stage: func(zipPath, root, version string, verify verifier) (stagedBundle, error) {
			if verify == nil {
				e.t.Error("stage called without a verifier")
			}
			_, err := os.Stat(zipPath)
			e.zipExistedAtStage = err == nil
			i := e.stageCalls
			e.stageCalls++
			if i < len(e.stageErrs) && e.stageErrs[i] != nil {
				return stagedBundle{}, e.stageErrs[i]
			}
			dir := filepath.Join(root, stagedPrefix+version)
			return stagedBundle{Dir: dir, App: filepath.Join(dir, "RHG Authenticator.app"), Version: version}, nil
		},
		verify: func(string, string) error { return nil },
		readyStaged: func(sb stagedBundle, _ applyDeps) (stagedBundle, error) {
			e.readyCalls++
			if e.readyErr != nil {
				return stagedBundle{}, e.readyErr
			}
			sb.App = filepath.Join(sb.Dir, "RHG Authenticator.app")
			return sb, nil
		},
		apply: func(root string, sb stagedBundle, currentBundle, running string, _ applyDeps) error {
			e.applyCalls++
			if root != e.root || running != e.running {
				e.t.Errorf("apply(%q, _, _, %q)", root, running)
			}
			e.appliedSB, e.appliedBundle = sb, currentBundle
			return e.applyErr
		},
		relaunch: func(bundle string) error {
			e.relaunchCalls = append(e.relaunchCalls, bundle)
			return e.relaunchErr
		},
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			if d != checkInterval {
				e.t.Errorf("ticker interval %v", d)
			}
			close(e.started)
			return e.tick, func() { e.stopped = true }
		},
	}
}

func (e *fakeEnv) manager() *Manager { return newManager(e.config(), e.deps()) }

// runFor starts Run, waits for the launch attempt, delivers ticks one by one
// (each send completes only once the previous attempt has finished), then
// cancels and waits for Run.
func (e *fakeEnv) runFor(m *Manager, ticks int) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()
	<-e.started
	for range ticks {
		e.tick <- time.Time{}
	}
	cancel()
	<-done
	if !e.stopped {
		e.t.Error("ticker not stopped")
	}
}

// hasLog reports whether a log line starts with prefix.
func (e *fakeEnv) hasLog(prefix string) bool {
	return slices.ContainsFunc(e.logs, func(l string) bool { return strings.HasPrefix(l, prefix) })
}

func (e *fakeEnv) requireLog(prefix string) {
	e.t.Helper()
	if !e.hasLog(prefix) {
		e.t.Errorf("no log line starting with %q in %q", prefix, e.logs)
	}
}

func (e *fakeEnv) requireStatuses(want ...Status) {
	e.t.Helper()
	if !slices.Equal(e.statuses, want) {
		e.t.Errorf("statuses = %+v, want %+v", e.statuses, want)
	}
}

// requireZipsGone fails if any downloaded zip still exists.
func (e *fakeEnv) requireZipsGone() {
	e.t.Helper()
	for _, z := range e.zips {
		if _, err := os.Lstat(z); !errors.Is(err, os.ErrNotExist) {
			e.t.Errorf("zip %s not deleted (err %v)", z, err)
		}
	}
}

// keepStaged makes cleanup report a staged bundle for version (on disk).
func (e *fakeEnv) keepStaged(version string) stagedBundle {
	e.t.Helper()
	if err := os.MkdirAll(e.root, 0o700); err != nil {
		e.t.Fatal(err)
	}
	populate(e.t, e.root, []string{stagedPrefix + version}, nil)
	sb := stagedBundle{Dir: filepath.Join(e.root, stagedPrefix+version), Version: version}
	e.cleanupRes.Staged = &sb
	return sb
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	return err == nil
}

var (
	readyStatus  = Status{State: StateReady, Version: "1.5.1", ReleaseURL: testReleaseURL}
	manualStatus = Status{State: StateManualOnly, Version: "1.5.1", ReleaseURL: testReleaseURL}
)

func TestManager_IdleToReady(t *testing.T) {
	e := newFakeEnv(t)
	e.runFor(e.manager(), 0)

	e.requireStatuses(readyStatus)
	if e.downloadCalls != 1 || e.stageCalls != 1 {
		t.Errorf("download %d, stage %d calls", e.downloadCalls, e.stageCalls)
	}
	if !e.zipExistedAtStage {
		t.Error("zip deleted before stage")
	}
	e.requireZipsGone()
	e.requireLog("update: ready v1.5.1")
}

func TestManager_ManualOnly(t *testing.T) {
	transient := fmt.Errorf("stage update: %w", errTransient)
	rejected := fmt.Errorf("stage update: %w: bad signature", errBundleRejected)
	tests := []struct {
		name     string
		setup    func(e *fakeEnv)
		move     bool
		reason   string
		download bool // a download is attempted
		marker   bool // an apply-failed marker exists afterwards
	}{
		{name: "translocated", setup: func(e *fakeEnv) { e.eligOK, e.reason = false, reasonTranslocate }, move: true, reason: reasonTranslocate},
		{name: "outside applications", setup: func(e *fakeEnv) { e.eligOK, e.reason = false, reasonOutside }, move: true, reason: reasonOutside},
		{name: "not writable", setup: func(e *fakeEnv) { e.eligOK, e.reason = false, reasonNotWritable }, reason: reasonNotWritable},
		{name: "not a bundle", setup: func(e *fakeEnv) { e.eligOK, e.reason = false, reasonNotBundle }, reason: reasonNotBundle},
		{name: "non-darwin", setup: func(e *fakeEnv) { e.eligBundle, e.eligOK, e.reason = "", false, reasonUnsupported }, reason: reasonUnsupported},
		{name: "no asset", setup: func(e *fakeEnv) { e.checks = []CheckResult{available("v1.5.1", false)} }, reason: reasonNoAsset},
		{name: "apply-failed marker on disk", setup: func(e *fakeEnv) {
			if err := markApplyFailed(e.root, "1.5.1"); err != nil {
				e.t.Fatal(err)
			}
		}, reason: reasonApplyFailed, marker: true},
		{name: "apply-failed from cleanup", setup: func(e *fakeEnv) { e.cleanupRes.ApplyFailed = []string{"1.5.1"} }, reason: reasonApplyFailed},
		{name: "download error", setup: func(e *fakeEnv) { e.downloadErr = errors.New("HTTP 500") }, reason: reasonDownloadFailed, download: true},
		{name: "transient stage error", setup: func(e *fakeEnv) { e.stageErrs = []error{transient} }, reason: reasonStageFailed, download: true},
		{name: "rejected bundle", setup: func(e *fakeEnv) { e.stageErrs = []error{rejected} }, reason: reasonRejected, download: true, marker: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFakeEnv(t)
			tt.setup(e)
			e.runFor(e.manager(), 0)

			want := manualStatus
			want.MoveToApplications = tt.move
			e.requireStatuses(want)
			e.requireLog("update: manual only v1.5.1 (" + tt.reason + ")")
			if got := e.downloadCalls > 0; got != tt.download {
				t.Errorf("download attempted = %v, want %v", got, tt.download)
			}
			if got := isApplyFailed(e.root, "1.5.1"); got != tt.marker {
				t.Errorf("apply-failed marker = %v, want %v", got, tt.marker)
			}
			e.requireZipsGone()
		})
	}
}

func TestManager_IneligibleLogged(t *testing.T) {
	e := newFakeEnv(t)
	e.eligOK, e.reason = false, reasonTranslocate
	e.runFor(e.manager(), 0)
	e.requireLog("update: not eligible for in-app update: translocated")
}

func TestManager_ZipDeletedAfterStage(t *testing.T) {
	for _, stageErr := range []error{nil, errors.New("disk full"), fmt.Errorf("%w: x", errBundleRejected)} {
		t.Run(fmt.Sprint(stageErr), func(t *testing.T) {
			e := newFakeEnv(t)
			e.stageErrs = []error{stageErr}
			e.runFor(e.manager(), 0)
			if len(e.zips) != 1 || !e.zipExistedAtStage {
				t.Fatalf("zips %v, existed at stage %v", e.zips, e.zipExistedAtStage)
			}
			e.requireZipsGone()
		})
	}
}

func TestManager_ZipRemoveFailureLogged(t *testing.T) {
	e := newFakeEnv(t)
	e.downloadDir = true // a non-empty directory cannot be os.Remove'd
	e.runFor(e.manager(), 0)
	e.requireLog("update: remove download: ")
	e.requireStatuses(readyStatus)
}

func TestManager_TransientStageRetriedOnTick(t *testing.T) {
	e := newFakeEnv(t)
	e.stageErrs = []error{fmt.Errorf("stage update: %w", errTransient), errors.New("no space left")}
	e.runFor(e.manager(), 2)

	if e.stageCalls != 3 {
		t.Fatalf("stage calls = %d, want 3", e.stageCalls)
	}
	if isApplyFailed(e.root, "1.5.1") {
		t.Error("transient stage error wrote an apply-failed marker")
	}
	// ManualOnly is reported once (unchanged on the second failure), then Ready.
	e.requireStatuses(manualStatus, readyStatus)
	e.requireZipsGone()
}

func TestManager_RejectedStaysManualWithoutRedownload(t *testing.T) {
	e := newFakeEnv(t)
	e.stageErrs = []error{fmt.Errorf("stage update: %w: bad", errBundleRejected)}
	e.runFor(e.manager(), 2)

	if e.downloadCalls != 1 {
		t.Errorf("download calls = %d, want 1", e.downloadCalls)
	}
	e.requireStatuses(manualStatus)
	if !exists(t, filepath.Join(e.root, applyFailedPrefix+"1.5.1")) {
		t.Error("marker missing")
	}
}

func TestManager_MarkerWriteFailureLogged(t *testing.T) {
	e := newFakeEnv(t)
	// A file where the staging root should be: last-version and the marker
	// cannot be written.
	if err := os.WriteFile(e.root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.downloadErr = nil
	e.stageErrs = []error{fmt.Errorf("%w: bad", errBundleRejected)}
	m := e.manager()
	m.deps.download = func(context.Context, string, string, string) (string, error) {
		return filepath.Join(e.dataDir, "missing.zip"), nil
	}
	e.runFor(m, 1)

	// One from writeLastVersion, one from markApplyFailed.
	n := 0
	for _, l := range e.logs {
		if strings.HasPrefix(l, "update: create staging root") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("logs %q: want 2 staging-root failures", e.logs)
	}
	// The in-memory record keeps the version manual-only without a marker.
	if e.stageCalls != 1 {
		t.Errorf("stage calls = %d, want 1", e.stageCalls)
	}
	e.requireStatuses(manualStatus)
}

func TestManager_ReadySkipsRecheck(t *testing.T) {
	e := newFakeEnv(t)
	e.runFor(e.manager(), 3)
	if e.checkCalls != 1 {
		t.Errorf("check calls = %d, want 1", e.checkCalls)
	}
	e.requireStatuses(readyStatus)
}

func TestManager_UpToDate(t *testing.T) {
	e := newFakeEnv(t)
	e.checks = []CheckResult{{LatestVersion: "v1.5.0", DownloadURL: testReleaseURL, CurrentVersion: "v1.5.0"}}
	e.runFor(e.manager(), 1)

	if e.checkCalls != 2 {
		t.Errorf("check calls = %d, want 2", e.checkCalls)
	}
	if !slices.Contains(e.logs, "update: up to date") {
		t.Errorf("logs %q lack exact %q", e.logs, "update: up to date")
	}
	e.requireStatuses() // Idle is the initial state: no change to report
}

func TestManager_UpToDateClearsManualOnly(t *testing.T) {
	e := newFakeEnv(t)
	e.checks = []CheckResult{available("v1.5.1", false), {LatestVersion: "v1.5.0"}}
	e.runFor(e.manager(), 1)
	e.requireStatuses(Status{State: StateManualOnly, Version: "1.5.1", ReleaseURL: testReleaseURL}, Status{})
}

func TestManager_CheckFailedKeepsState(t *testing.T) {
	e := newFakeEnv(t)
	e.checks = []CheckResult{available("v1.5.1", false), {}}
	e.runFor(e.manager(), 2)
	e.requireLog("update: check failed")
	e.requireStatuses(Status{State: StateManualOnly, Version: "1.5.1", ReleaseURL: testReleaseURL})
}

func TestManager_InvalidReleaseVersion(t *testing.T) {
	e := newFakeEnv(t)
	e.checks = []CheckResult{{UpdateAvailable: true, LatestVersion: "garbage"}}
	e.runFor(e.manager(), 0)
	e.requireLog("update: invalid release version")
	e.requireStatuses()
	if e.downloadCalls != 0 {
		t.Error("downloaded for an invalid version")
	}
}

func TestManager_StagedReuse(t *testing.T) {
	t.Run("same version is ready without download", func(t *testing.T) {
		e := newFakeEnv(t)
		sb := e.keepStaged("1.5.1")
		e.runFor(e.manager(), 0)
		if e.downloadCalls != 0 || e.readyCalls != 1 {
			t.Errorf("download %d, readyStaged %d calls", e.downloadCalls, e.readyCalls)
		}
		e.requireStatuses(readyStatus)
		if !exists(t, sb.Dir) {
			t.Error("staged dir removed")
		}
	})

	t.Run("offline reuses staged with local release URL", func(t *testing.T) {
		e := newFakeEnv(t)
		e.checks = []CheckResult{{}}
		e.keepStaged("1.5.1")
		e.runFor(e.manager(), 0)
		e.requireStatuses(Status{State: StateReady, Version: "1.5.1", ReleaseURL: "https://github.com/o/r/releases/tag/v1.5.1"})
	})

	t.Run("failed re-verify is discarded then downloaded", func(t *testing.T) {
		e := newFakeEnv(t)
		sb := e.keepStaged("1.5.1")
		e.readyErr = errors.New("signature invalid")
		e.runFor(e.manager(), 0)
		e.requireLog("update: discarded staged 1.5.1: signature invalid")
		if exists(t, sb.Dir) {
			t.Error("rejected staged dir not removed")
		}
		if e.downloadCalls != 1 {
			t.Errorf("download calls = %d, want 1", e.downloadCalls)
		}
		e.requireStatuses(readyStatus)
	})

	t.Run("offline failed re-verify is considered once", func(t *testing.T) {
		e := newFakeEnv(t)
		e.checks = []CheckResult{{}}
		e.keepStaged("1.5.1")
		e.readyErr = errors.New("bad")
		e.runFor(e.manager(), 2)
		if e.readyCalls != 1 {
			t.Errorf("readyStaged calls = %d, want 1", e.readyCalls)
		}
		e.requireStatuses()
	})

	t.Run("superseded staged is removed", func(t *testing.T) {
		e := newFakeEnv(t)
		old := e.keepStaged("1.5.0")
		e.cleanupRes.Staged.Version = "1.4.9" // older than the 1.5.1 release
		e.runFor(e.manager(), 0)
		e.requireLog("update: removing superseded staged 1.4.9")
		if exists(t, old.Dir) {
			t.Error("superseded staged dir not removed")
		}
		if e.readyCalls != 0 || e.downloadCalls != 1 {
			t.Errorf("readyStaged %d, download %d calls", e.readyCalls, e.downloadCalls)
		}
		e.requireStatuses(readyStatus)
	})

	t.Run("ineligible never reuses staged", func(t *testing.T) {
		for _, checks := range [][]CheckResult{{available("v1.5.1", true)}, {{}}} {
			e := newFakeEnv(t)
			sb := e.keepStaged("1.5.1")
			e.checks = checks
			e.eligOK, e.reason = false, reasonOutside
			e.runFor(e.manager(), 0)
			if e.readyCalls != 0 || e.downloadCalls != 0 {
				t.Errorf("readyStaged %d, download %d calls", e.readyCalls, e.downloadCalls)
			}
			if !exists(t, sb.Dir) {
				t.Error("staged dir removed while ineligible")
			}
		}
	})

	t.Run("remove failure is logged", func(t *testing.T) {
		e := newFakeEnv(t)
		e.keepStaged("1.5.1")
		// RemoveAll rejects a path ending in "." on every platform.
		e.cleanupRes.Staged.Dir += string(filepath.Separator) + "."
		e.readyErr = errors.New("bad")
		e.runFor(e.manager(), 0)
		e.requireLog("update: remove staged 1.5.1: ")
	})
}

func TestManager_CleanupErrorLoggedAndContinues(t *testing.T) {
	e := newFakeEnv(t)
	e.cleanupErr = errors.New("permission denied")
	e.runFor(e.manager(), 0)
	e.requireLog("update: cleanup: permission denied")
	e.requireStatuses(readyStatus)
}

func TestManager_UpdatedBanner(t *testing.T) {
	tests := []struct {
		name    string
		stored  *string // nil: no last-version file
		running string
		want    [][2]string
		written string // expected last-version contents afterwards ("" = absent)
	}{
		{name: "upgraded", stored: ptr("v1.4.0"), running: "v1.5.0",
			want: [][2]string{{"1.5.0", "https://github.com/o/r/releases/tag/v1.5.0"}}, written: "v1.5.0"},
		{name: "first run", running: "v1.5.0", written: "v1.5.0"},
		{name: "same version", stored: ptr("v1.5.0"), running: "v1.5.0", written: "v1.5.0"},
		{name: "downgrade", stored: ptr("v1.6.0"), running: "v1.5.0", written: "v1.5.0"},
		{name: "dev build", stored: ptr("v1.4.0"), running: "dev", written: "v1.4.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFakeEnv(t)
			e.running = tt.running
			e.checks = []CheckResult{{}} // offline: the banner needs no network
			if tt.stored != nil {
				if err := writeLastVersion(e.dataDir, *tt.stored); err != nil {
					t.Fatal(err)
				}
			}
			e.runFor(e.manager(), 0)
			if !slices.Equal(e.updated, tt.want) {
				t.Errorf("OnUpdated calls = %v, want %v", e.updated, tt.want)
			}
			got, _ := readLastVersion(e.dataDir)
			if got != tt.written {
				t.Errorf("last-version = %q, want %q", got, tt.written)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestManager_CancelledBeforeCheck(t *testing.T) {
	e := newFakeEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.manager().Run(ctx)
	if e.checkCalls != 0 {
		t.Errorf("check calls = %d, want 0", e.checkCalls)
	}
}

func TestManager_DownloadCancelledReportsNothing(t *testing.T) {
	e := newFakeEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	m := e.manager()
	m.deps.download = func(context.Context, string, string, string) (string, error) {
		cancel()
		return "", context.Canceled
	}
	m.Run(ctx)
	e.requireStatuses()
	if e.hasLog("update: download") {
		t.Errorf("logged a shutdown download failure: %q", e.logs)
	}
}

func TestManager_ApplyIfReady(t *testing.T) {
	tests := []struct {
		name         string
		ready        bool
		relaunch     bool
		applyErr     error
		relaunchErr  error
		wantApply    bool
		wantRelaunch bool
		wantLog      string
	}{
		{name: "not ready", relaunch: true},
		{name: "ready, no relaunch", ready: true, wantApply: true, wantLog: "update: applied v1.5.1"},
		{name: "ready, relaunch", ready: true, relaunch: true, wantApply: true, wantRelaunch: true, wantLog: "update: applied v1.5.1"},
		{name: "apply fails", ready: true, relaunch: true, applyErr: errors.New("swap failed"), wantApply: true,
			wantLog: "update: apply v1.5.1 failed: swap failed"},
		{name: "relaunch fails", ready: true, relaunch: true, relaunchErr: errors.New("no open"), wantApply: true,
			wantRelaunch: true, wantLog: "update: relaunch: no open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFakeEnv(t)
			if !tt.ready {
				e.checks = []CheckResult{available("v1.5.1", false)}
			}
			e.applyErr, e.relaunchErr = tt.applyErr, tt.relaunchErr
			m := e.manager()
			e.runFor(m, 0)
			m.ApplyIfReady(tt.relaunch)
			m.ApplyIfReady(tt.relaunch) // at most once

			if got := e.applyCalls; got != map[bool]int{true: 1}[tt.wantApply] {
				t.Errorf("apply calls = %d, want apply %v", got, tt.wantApply)
			}
			if tt.wantApply {
				if e.appliedBundle != testRunningBundle || e.appliedSB.Version != "1.5.1" || e.appliedSB.App == "" {
					t.Errorf("apply(%+v, %q)", e.appliedSB, e.appliedBundle)
				}
			}
			wantRelaunch := []string(nil)
			if tt.wantRelaunch {
				wantRelaunch = []string{testRunningBundle}
			}
			if !slices.Equal(e.relaunchCalls, wantRelaunch) {
				t.Errorf("relaunch calls = %q, want %q", e.relaunchCalls, wantRelaunch)
			}
			if tt.wantLog != "" && !slices.Contains(e.logs, tt.wantLog) {
				t.Errorf("logs %q lack exact %q", e.logs, tt.wantLog)
			}
			if !tt.wantApply && e.hasLog("update: appl") {
				t.Errorf("unexpected apply log: %q", e.logs)
			}
		})
	}
}

func TestManager_ApplyIfReadyWithoutRun(t *testing.T) {
	e := newFakeEnv(t)
	e.manager().ApplyIfReady(true)
	if e.applyCalls != 0 || len(e.relaunchCalls) != 0 {
		t.Errorf("apply %d, relaunch %v", e.applyCalls, e.relaunchCalls)
	}
}

func TestManager_ApplyIfReadyConcurrentWithRun(t *testing.T) {
	e := newFakeEnv(t)
	m := e.manager()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()
	m.ApplyIfReady(false) // may or may not see Ready; must not race
	cancel()
	<-done
}

func TestManager_NilCallbacks(t *testing.T) {
	e := newFakeEnv(t)
	if err := writeLastVersion(e.dataDir, "v1.4.0"); err != nil {
		t.Fatal(err)
	}
	e.eligOK = false
	m := newManager(Config{DataDir: e.dataDir, Running: e.running, Owner: "o", Repo: "r"}, e.deps())
	e.runFor(m, 0)
	m.ApplyIfReady(true)
}

func TestNewManager_ProductionDeps(t *testing.T) {
	m := NewManager(Config{DataDir: t.TempDir()})
	d := m.deps
	if d.check == nil || d.eligible == nil || d.cleanup == nil || d.download == nil || d.stage == nil ||
		d.verify == nil || d.readyStaged == nil || d.apply == nil || d.relaunch == nil ||
		d.applyDeps.verify == nil || d.newTicker == nil {
		t.Fatalf("missing production dependency: %+v", d)
	}
	tick, stop := d.newTicker(time.Millisecond)
	defer stop()
	select {
	case <-tick:
	case <-time.After(5 * time.Second):
		t.Fatal("production ticker never fired")
	}
}
