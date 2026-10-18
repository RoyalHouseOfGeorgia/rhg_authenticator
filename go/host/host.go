// Package host holds the process start-up steps shared by the RHG
// Authenticator front ends: the data directory, the diagnostic log with its
// process-wide hooks (stdlib log capture, goroutine panic handler, runtime
// crash output), the signing service and the update manager. The package has
// no UI dependency.
package host

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// AppDirName is the data directory's name within the user config directory.
const AppDirName = "rhg-authenticator"

// userConfigDir, setCrashOutput and newService are the os, runtime and
// service calls the start-up steps make, replaceable in tests.
var (
	userConfigDir  = os.UserConfigDir
	setCrashOutput = debug.SetCrashOutput
	newService     = service.New
)

// DataDir returns the app data directory, creating it (0o700) if needed: the
// override when set, which must be absolute, else AppDirName in the user
// config directory. Error texts are user-facing.
func DataDir(override string) (string, error) {
	dir := override
	if dir == "" {
		configDir, err := userConfigDir()
		if err != nil {
			return "", fmt.Errorf("Cannot determine config directory: %w", err)
		}
		dir = filepath.Join(configDir, AppDirName)
	} else if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("Data directory must be an absolute path: %q.", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("Cannot create data directory: %w", err)
	}
	return dir, nil
}

// Logs is the open diagnostic log and the process-wide hooks that write to
// it. Only one is active at a time: OpenLogs replaces the previous one.
type Logs struct {
	Logger       *debuglog.Logger
	onPanic      func()
	releaseCrash func()
}

var (
	// active is the Logs the goroutine panic handler writes to.
	active atomic.Pointer[Logs]
	// handlerOnce installs the panic handler once per process: safego's
	// handler may not change while goroutines run.
	handlerOnce sync.Once
)

// OpenLogs prunes the diagnostic log in dataDir, then routes the runtime's
// crash reports, the standard library logger and safego goroutine panics into
// it, and logs the start-up line. onPanic (if not nil) runs on the panicking
// goroutine after the panic is logged, so the host can tell the user. Call it
// before launching goroutines. Failures are logged to the log itself.
func OpenLogs(dataDir string, onPanic func()) *Logs {
	path := filepath.Join(dataDir, debuglog.FileName)
	// Prune first: it replaces the file, and crash output holds a handle on it.
	pruneErr := debuglog.Prune(path, debuglog.LogRetention, time.Now())
	l := &Logs{Logger: debuglog.New(path), onPanic: onPanic}
	if pruneErr != nil {
		l.Logger.Logf("warning: log prune failed: %v", pruneErr)
	}
	if err := l.setCrashOutput(path); err != nil {
		l.Logger.Logf("warning: %v", err)
	}
	debuglog.CaptureStdlib(l.Logger)
	active.Store(l)
	handlerOnce.Do(func() { safego.SetPanicHandler(handlePanic) })

	msg := "RHG Authenticator starting (version: " + buildinfo.Version + ")"
	if buildinfo.IsDebug() {
		msg += " (debug mode)"
	}
	l.Logger.Log(msg)
	return l
}

// setCrashOutput appends the runtime's fatal-error and unrecovered-panic
// reports to the file at path (created 0o600 if missing) as well as stderr.
func (l *Logs) setCrashOutput(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open crash output: %w", err)
	}
	// The runtime duplicates the handle, so f is closed either way.
	err = setCrashOutput(f, debug.CrashOptions{})
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("set crash output: %w", err)
	}
	l.releaseCrash = func() { _ = setCrashOutput(nil, debug.CrashOptions{}) }
	return nil
}

// Close points crash output and the standard library logger back at stderr
// and stops goroutine panics reaching l, so a host can undo a failed start-up
// or open the log again elsewhere.
func (l *Logs) Close() {
	if !active.CompareAndSwap(l, nil) {
		return // already closed, or replaced by a later OpenLogs
	}
	if l.releaseCrash != nil {
		l.releaseCrash()
	}
	debuglog.ReleaseStdlib()
}

// handlePanic is the process's safego panic handler: stderr, then the active
// Logs (its log entry and its onPanic).
func handlePanic(r any, stack []byte) {
	fmt.Fprintf(os.Stderr, "goroutine panic: %v\n%s\n", r, stack)
	l := active.Load()
	if l == nil {
		return
	}
	l.Logger.Logf("PANIC (goroutine): %s %s", core.SanitizeForLog(fmt.Sprint(r)), stack)
	if l.onPanic != nil {
		l.onPanic()
	}
}

// NewService returns service.New(cfg) with an empty RegistryURL or
// RevocationURL replaced by the production default. Like service.New it
// blocks on the registry fetch and starts offline when that fails. The error
// text is user-facing.
func NewService(cfg service.Config) (*service.App, error) {
	if cfg.RegistryURL == "" {
		cfg.RegistryURL = registry.DefaultRegistryURL
	}
	if cfg.RevocationURL == "" {
		cfg.RevocationURL = registry.DefaultRevocationURL
	}
	svc, err := newService(cfg)
	if err != nil {
		return nil, fmt.Errorf("Cannot start signing service: %w", err)
	}
	return svc, nil
}

// UpdateConfig returns the update.Config for the running build: the app's
// GitHub releases, staged under dataDir. The caller sets the callbacks, builds
// the update.Manager and runs Manager.Run on a safego.Go goroutine.
func UpdateConfig(dataDir string) update.Config {
	return update.Config{
		DataDir: dataDir,
		Running: buildinfo.Version,
		Owner:   ghapi.DefaultOwner,
		Repo:    ghapi.DefaultRepo,
	}
}
