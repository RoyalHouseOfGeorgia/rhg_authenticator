package host

import (
	"context"
	"errors"
	stdlog "log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// fakeCrashOutput replaces setCrashOutput for t, recording each file passed.
func fakeCrashOutput(t *testing.T, err error) *[]*os.File {
	t.Helper()
	var calls []*os.File
	prev := setCrashOutput
	setCrashOutput = func(f *os.File, _ debug.CrashOptions) error {
		calls = append(calls, f)
		return err
	}
	t.Cleanup(func() { setCrashOutput = prev })
	return &calls
}

// openLogs runs OpenLogs on a fresh temp data dir for t and closes the Logs
// (restoring the standard logger) before the dir is removed.
func openLogs(t *testing.T, onPanic func()) (*Logs, string) {
	t.Helper()
	dir := t.TempDir()
	w, flags := stdlog.Writer(), stdlog.Flags()
	l := OpenLogs(dir, onPanic)
	t.Cleanup(func() {
		l.Close()
		stdlog.SetOutput(w)
		stdlog.SetFlags(flags)
	})
	return l, dir
}

// readLog returns the diagnostic log in dir.
func readLog(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, debuglog.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// waitForLog waits until the diagnostic log in dir contains want.
func waitForLog(t *testing.T, dir, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(readLog(t, dir), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %q: %q", want, readLog(t, dir))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type nopPrompter struct{}

func (nopPrompter) RequestPIN(context.Context, bool) (string, bool, error) { return "", false, nil }

type nopEvents struct{}

func (nopEvents) Emit(string, any) {}

func TestOpenLogs(t *testing.T) {
	calls := fakeCrashOutput(t, nil)
	dir := t.TempDir()
	logPath := filepath.Join(dir, debuglog.FileName)
	// A stale entry and its continuation line are pruned before crash output
	// is pointed at the file.
	stale := "[" + time.Now().Add(-2*debuglog.LogRetention).UTC().Format(time.RFC3339) + "] stale entry\nstale crash line\n"
	if err := os.WriteFile(logPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	w, flags := stdlog.Writer(), stdlog.Flags()
	t.Cleanup(func() { stdlog.SetOutput(w); stdlog.SetFlags(flags) })

	panicked := make(chan struct{})
	l := OpenLogs(dir, func() { close(panicked) })
	t.Cleanup(l.Close)

	if l.Logger.Path() != logPath {
		t.Errorf("logger path = %q, want %q", l.Logger.Path(), logPath)
	}
	if got := readLog(t, dir); strings.Contains(got, "stale") {
		t.Errorf("stale entry not pruned: %q", got)
	}
	if len(*calls) != 1 || (*calls)[0] == nil || (*calls)[0].Name() != logPath {
		t.Fatalf("crash output calls = %v, want the log file", *calls)
	}
	// The runtime keeps its own duplicate; ours is closed straight away.
	if _, err := (*calls)[0].Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("crash output file still open: write err = %v", err)
	}
	want := "RHG Authenticator starting (version: " + buildinfo.Version + ")"
	if !strings.Contains(readLog(t, dir), want) {
		t.Errorf("start line %q not logged", want)
	}

	stdlog.Print("stdlib line")
	if !strings.Contains(readLog(t, dir), "stdlib line") {
		t.Error("stdlib log not captured")
	}

	safego.Go(func() { panic("boom‮") })
	select {
	case <-panicked:
	case <-time.After(5 * time.Second):
		t.Fatal("panic callback not called")
	}
	if got := readLog(t, dir); !strings.Contains(got, "PANIC (goroutine): boom ") || strings.Contains(got, "‮") {
		t.Errorf("panic not logged sanitized: %q", got)
	}

	l.Close()
	if len(*calls) != 2 || (*calls)[1] != nil {
		t.Errorf("Close did not reset crash output: calls = %v", *calls)
	}
	if stdlog.Writer() != os.Stderr || stdlog.Flags() != stdlog.LstdFlags {
		t.Errorf("Close did not release stdlib: writer = %v, flags = %d", stdlog.Writer(), stdlog.Flags())
	}
	l.Close() // a second Close is a no-op
	if len(*calls) != 2 {
		t.Errorf("second Close reset crash output again: calls = %d", len(*calls))
	}
}

// TestOpenLogs_Reopen checks that a second OpenLogs takes over the panic
// handler and that closing the first one doesn't undo the second.
func TestOpenLogs_Reopen(t *testing.T) {
	fakeCrashOutput(t, nil)
	first, firstDir := openLogs(t, nil)
	second, secondDir := openLogs(t, nil)

	first.Close()
	if active.Load() != second {
		t.Fatal("closing a replaced Logs deactivated the current one")
	}
	safego.Go(func() { panic("second") })
	waitForLog(t, secondDir, "PANIC (goroutine): second")
	if strings.Contains(readLog(t, firstDir), "PANIC") {
		t.Error("panic logged to the replaced log")
	}

	second.Close()
	if active.Load() != nil {
		t.Error("Close left the Logs active")
	}
	handlePanic("closed", nil) // stderr only, nothing logged
	if strings.Contains(readLog(t, secondDir), "closed") {
		t.Error("panic logged after Close")
	}
}

func TestOpenLogs_Failures(t *testing.T) {
	fakeCrashOutput(t, errors.New("unsupported"))
	l, dir := openLogs(t, nil)
	if !strings.Contains(readLog(t, dir), "warning: set crash output: unsupported") {
		t.Errorf("crash output failure not logged: %q", readLog(t, dir))
	}
	if l.releaseCrash != nil {
		t.Error("release set although crash output failed")
	}

	// A log that fails to rewrite logs the prune failure into the log. The
	// prune writes through debuglog's path+".tmp", which a directory blocks.
	dir = t.TempDir()
	logPath := filepath.Join(dir, debuglog.FileName)
	if err := os.WriteFile(logPath, []byte("untimestamped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(logPath+".tmp", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	w, flags := stdlog.Writer(), stdlog.Flags()
	l = OpenLogs(dir, nil)
	t.Cleanup(func() { l.Close(); stdlog.SetOutput(w); stdlog.SetFlags(flags) })
	if !strings.Contains(readLog(t, dir), "warning: log prune failed: ") {
		t.Errorf("prune failure not logged: %q", readLog(t, dir))
	}
}

func TestSetCrashOutput_OpenFailure(t *testing.T) {
	calls := fakeCrashOutput(t, nil)
	l := &Logs{}
	err := l.setCrashOutput(filepath.Join(t.TempDir(), "absent", debuglog.FileName))
	if err == nil || !strings.HasPrefix(err.Error(), "open crash output: ") {
		t.Errorf("err = %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("open failure reached the runtime: calls = %d", len(*calls))
	}
}

func TestSetCrashOutput_FileMode(t *testing.T) {
	fakeCrashOutput(t, nil)
	path := filepath.Join(t.TempDir(), debuglog.FileName)
	if err := (&Logs{}).setCrashOutput(path); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("log not created: %v", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestNewService_Offline checks that a dead registry is not a start-up error.
func TestNewService_Offline(t *testing.T) {
	fakeCrashOutput(t, nil)
	l, dir := openLogs(t, nil)
	srv := httptest.NewServer(nil)
	srv.Close()
	svc, err := NewService(service.Config{
		DataDir: dir, Logger: l.Logger, Prompter: nopPrompter{}, Events: nopEvents{},
		RegistryURL: srv.URL, RevocationURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(svc.Close)
	if svc.Info().Online {
		t.Error("service online with a dead registry")
	}
	if !strings.Contains(readLog(t, dir), "registry fetch: online=false") {
		t.Error("registry fetch result not logged")
	}
}

func TestDataDir(t *testing.T) {
	dir, err := DataDir(filepath.Join(t.TempDir(), "data", "nested"))
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("data dir not created: %v", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestDataDir_Default(t *testing.T) {
	cfg := t.TempDir()
	prev := userConfigDir
	userConfigDir = func() (string, error) { return cfg, nil }
	t.Cleanup(func() { userConfigDir = prev })

	dir, err := DataDir("")
	if err != nil || dir != filepath.Join(cfg, AppDirName) {
		t.Fatalf("DataDir = %q, %v", dir, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("not created: %v", err)
	}
}

func TestDataDir_Errors(t *testing.T) {
	prev := userConfigDir
	t.Cleanup(func() { userConfigDir = prev })

	userConfigDir = func() (string, error) { return "", errors.New("no home") }
	if _, err := DataDir(""); err == nil || err.Error() != "Cannot determine config directory: no home" {
		t.Errorf("no config dir: err = %v", err)
	}

	if _, err := DataDir(filepath.Join("relative", "dir")); err == nil || !strings.HasPrefix(err.Error(), "Data directory must be an absolute path: ") || !strings.HasSuffix(err.Error(), ".") {
		t.Errorf("relative override: err = %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DataDir(filepath.Join(file, "sub")); err == nil || !strings.HasPrefix(err.Error(), "Cannot create data directory: ") {
		t.Errorf("uncreatable: err = %v", err)
	}
}

func TestNewService_URLsAndError(t *testing.T) {
	prev := newService
	t.Cleanup(func() { newService = prev })
	var got service.Config
	stop := errors.New("stop")
	newService = func(cfg service.Config) (*service.App, error) {
		got = cfg
		return nil, stop
	}

	_, err := NewService(service.Config{DataDir: "/d"})
	if !errors.Is(err, stop) || err.Error() != "Cannot start signing service: stop" {
		t.Errorf("err = %v, want the wrapped service error", err)
	}
	if got.RegistryURL != registry.DefaultRegistryURL || got.RevocationURL != registry.DefaultRevocationURL || got.DataDir != "/d" {
		t.Errorf("defaults: config = %+v", got)
	}
	_, _ = NewService(service.Config{RegistryURL: "http://r", RevocationURL: "http://v"})
	if got.RegistryURL != "http://r" || got.RevocationURL != "http://v" {
		t.Errorf("overrides: config = %+v", got)
	}
}

func TestUpdateConfig(t *testing.T) {
	cfg := UpdateConfig("/data")
	if cfg.DataDir != "/data" || cfg.Running != buildinfo.Version ||
		cfg.Owner != ghapi.DefaultOwner || cfg.Repo != ghapi.DefaultRepo {
		t.Errorf("config = %+v", cfg)
	}
	if cfg.OnStatus != nil || cfg.OnUpdated != nil || cfg.Logf != nil {
		t.Error("callbacks set; the caller owns them")
	}
}
