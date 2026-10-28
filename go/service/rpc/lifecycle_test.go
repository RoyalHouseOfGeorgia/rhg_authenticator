package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/host"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// waitTimeout bounds every wait for an event or a blocked call.
const waitTimeout = 10 * time.Second

// protectedPathMsg is the core's message for a save into its data folder.
const protectedPathMsg = "Choose a folder outside the app's data folder."

// eventSink records emitted events and wakes waiters on each one.
type eventSink struct {
	mu     sync.Mutex
	events []string
	notify chan struct{}
}

func newEventSink() *eventSink { return &eventSink{notify: make(chan struct{}, 1)} }

func (s *eventSink) add(b []byte) {
	s.mu.Lock()
	s.events = append(s.events, string(b))
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *eventSink) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

// named returns the data of every recorded event called name.
func (s *eventSink) named(t testing.TB, name string) []json.RawMessage {
	t.Helper()
	var out []json.RawMessage
	for _, e := range s.all() {
		var ev struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(e), &ev); err != nil {
			t.Fatalf("event %s: %v", e, err)
		}
		if ev.Event == name {
			out = append(out, ev.Data)
		}
	}
	return out
}

// wait returns the data of the nth (1-based) event called name, waiting for
// it.
func (s *eventSink) wait(t testing.TB, name string, n int) json.RawMessage {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		if got := s.named(t, name); len(got) >= n {
			return got[n-1]
		}
		select {
		case <-s.notify:
		case <-deadline:
			t.Fatalf("event %s #%d never arrived; got %v", name, n, s.all())
		}
	}
}

// fakeManager stands in for the update manager.
type fakeManager struct {
	cfg     update.Config
	running chan struct{} // receives once Run starts
	stopped chan struct{} // closed when Run returns
	applied chan bool     // receives each ApplyIfReady argument
}

func newFakeManager() *fakeManager {
	return &fakeManager{running: make(chan struct{}, 1), stopped: make(chan struct{}), applied: make(chan bool, 4)}
}

func (m *fakeManager) Run(ctx context.Context) {
	m.running <- struct{}{}
	<-ctx.Done()
	close(m.stopped)
}

func (m *fakeManager) ApplyIfReady(relaunch bool) { m.applied <- relaunch }

// lcHarness is a server driven through its whole lifecycle against a local
// registry server, with a fake keyring and update manager.
type lcHarness struct {
	srv  *server
	sink *eventSink
	mgr  *fakeManager
	reg  *httptest.Server
	tmp  string // a scratch dir; data dirs go inside it

	// With gate set, the registry handler signals entered and then waits for
	// the gate.
	gate    chan struct{}
	entered chan struct{}
}

// newLC returns a harness whose server has the sink attached. Cleanup shuts
// the server down and closes its logs (restoring the standard logger) before
// the scratch dir is removed.
func newLC(t *testing.T) *lcHarness {
	t.Helper()
	h := &lcHarness{srv: newServer(), sink: newEventSink(), mgr: newFakeManager()}
	body := `{"keys": [{"authority": "A", "from": "2025-01-01", "to": null, "algorithm": "Ed25519", "public_key": "` + testKeyB64(1) + `", "note": ""}]}`
	h.reg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/registry" {
			http.NotFound(w, r)
			return
		}
		if h.gate != nil {
			h.entered <- struct{}{}
			<-h.gate
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(h.reg.Close)
	h.tmp = t.TempDir()

	kr := ghapi.NewFakeKeyring()
	h.srv.newKeyring = func() ghapi.Keyring { return kr }
	h.srv.newService = h.localService
	h.srv.newManager = func(cfg update.Config) updateManager {
		h.mgr.cfg = cfg
		return h.mgr
	}
	h.srv.events.SetSink(h.sink.add)

	cleanupServer(t, h.srv)
	return h
}

// cleanupServer shuts srv down when the test ends and closes its logs,
// restoring the standard logger, before the test's temp dirs are removed.
func cleanupServer(t *testing.T, srv *server) {
	w, flags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		srv.Dispatch("app.shutdown", nil)
		srv.mu.Lock()
		logs := srv.logs
		srv.mu.Unlock()
		if logs != nil {
			logs.Close()
		}
		log.SetOutput(w)
		log.SetFlags(flags)
	})
}

func (h *lcHarness) call(t testing.TB, method, params string) envelope {
	t.Helper()
	return dispatch(t, h.srv, method, params)
}

// localService is the production service constructor pointed at the local
// registry and revocation list.
func (h *lcHarness) localService(cfg service.Config) (*service.App, error) {
	cfg.RegistryURL, cfg.RevocationURL = h.reg.URL+"/registry", h.reg.URL+"/revocations"
	return host.NewService(cfg)
}

// initParams returns app.init params for data dir dir.
func (h *lcHarness) initParams(dir string) string {
	return `{"dataDir":` + jsonString(dir) + `}`
}

// init runs app.init with a fresh data dir and asserts it succeeds.
func (h *lcHarness) init(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(h.tmp, "data")
	var info service.Info
	h.call(t, "app.init", h.initParams(dir)).ok(t, &info)
	if !info.Online || info.ActiveKeys != 1 || len(info.StatusItems) != 3 || info.StatusItems[0] != "Active keys: 1" {
		t.Fatalf("info = %+v", info)
	}
	return dir
}

// startAndSettle runs app.start and waits for the App's start-up work (the
// session restore and registry load, the history load and revocation fetch)
// to finish, so nothing writes to the data dir afterwards.
func (h *lcHarness) startAndSettle(t testing.TB) {
	t.Helper()
	h.call(t, "app.start", ``).ok(t, nil)
	for _, e := range []string{service.EventRegistryChanged, service.EventHistoryChanged, service.EventRevocationsChanged} {
		h.sink.wait(t, e, 1)
	}
	select {
	case <-h.mgr.running:
	case <-time.After(waitTimeout):
		t.Fatal("update manager never ran")
	}
}

func (h *lcHarness) state() lifecycle {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	return h.srv.state
}

func readLogIn(t testing.TB, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, debuglog.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (h *lcHarness) wantCanQuit(t testing.TB, dirty bool) {
	t.Helper()
	var r struct{ Dirty *bool }
	h.call(t, "app.canQuit", ``).ok(t, &r)
	if r.Dirty == nil || *r.Dirty != dirty {
		t.Fatalf("canQuit dirty = %v, want %v", r.Dirty, dirty)
	}
}

// gatedMethods are every method that needs stateReady.
func gatedMethods() []string {
	var out []string
	for name := range methodTable() {
		if !anyStateMethods[name] {
			out = append(out, name)
		}
	}
	return out
}

func TestInit_Rejects(t *testing.T) {
	h := newLC(t)
	good := filepath.Join(h.tmp, "data")

	h.srv.events.SetSink(nil)
	h.call(t, "app.init", h.initParams(good)).fails(t, CodeInput, errNoCallback.msg)
	h.srv.events.SetSink(h.sink.add)

	for _, tc := range []struct{ name, params, msg string }{
		{"relative dataDir", `{"dataDir":"rel/dir"}`, errBadDataDir.msg},
		{"unknown field", `{"dataDir":"/x","pin":"1"}`, msgBadParams},
		{"registry URL override", `{"dataDir":"/x","registryURL":"https://example.com/r"}`, msgBadParams},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.call(t, "app.init", tc.params).fails(t, CodeInput, tc.msg)
		})
	}
	if h.state() != stateNew {
		t.Fatalf("state = %v after rejected inits", h.state())
	}
	h.init(t)
}

func TestLifecycle_HappyPath(t *testing.T) {
	h := newLC(t)
	h.wantCanQuit(t, false) // new

	for _, m := range gatedMethods() {
		h.call(t, m, ``).fails(t, CodeInput, errNotReady.msg)
	}

	dir := h.init(t)
	if !strings.Contains(readLogIn(t, dir), "RHG Authenticator starting") {
		t.Error("diagnostic log not opened in the data dir")
	}
	h.call(t, "app.init", h.initParams(dir)).fails(t, CodeInput, errInitialized.msg)
	h.wantCanQuit(t, false) // ready, clean
	var info service.Info
	h.call(t, "app.info", ``).ok(t, &info)
	if !info.Online || len(info.StatusItems) != 3 {
		t.Errorf("info = %+v", info)
	}

	h.startAndSettle(t)
	h.call(t, "app.start", ``).fails(t, CodeInput, errStarted.msg)
	if h.mgr.cfg.DataDir != dir || h.mgr.cfg.OnStatus == nil || h.mgr.cfg.OnUpdated == nil || h.mgr.cfg.Logf == nil {
		t.Fatalf("update config = %+v", h.mgr.cfg)
	}
	h.mgr.cfg.Logf("update: test line %d", 7)
	if !strings.Contains(readLogIn(t, dir), "update: test line 7") {
		t.Error("update Logf does not reach the diagnostic log")
	}

	h.call(t, "registry.addEntry", `{"form":{"authority":"New","from":"2026-01-01","noExpiry":true},"publicKey":`+jsonString(testKeyB64(9))+`}`).ok(t, nil)
	h.wantCanQuit(t, true) // ready, dirty

	h.call(t, "app.shutdown", `{"relaunch":true}`).ok(t, nil)
	select {
	case r := <-h.mgr.applied:
		if !r {
			t.Error("ApplyIfReady(false), want true")
		}
	default:
		t.Fatal("ApplyIfReady not called")
	}
	select {
	case <-h.mgr.stopped:
	case <-time.After(waitTimeout):
		t.Fatal("update manager not stopped")
	}
	if h.srv.events.attached() {
		t.Error("event callback still attached after shutdown")
	}

	h.wantCanQuit(t, false) // shut down
	h.call(t, "app.shutdown", `{"relaunch":true}`).ok(t, nil)
	if len(h.mgr.applied) != 0 {
		t.Error("second shutdown applied again")
	}
	for _, m := range append(gatedMethods(), "app.init") {
		h.call(t, m, ``).fails(t, CodeInput, errShutDown.msg)
	}
	h.call(t, "app.shutdown", `{"x":1}`).fails(t, CodeInput, msgBadParams)
}

func TestShutdown_WithoutStart(t *testing.T) {
	h := newLC(t)
	h.init(t)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	if len(h.mgr.applied) != 0 {
		t.Error("ApplyIfReady called without a manager")
	}
	h.call(t, "app.start", ``).fails(t, CodeInput, errShutDown.msg)
}

func TestShutdown_BeforeInit(t *testing.T) {
	h := newLC(t)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	h.wantCanQuit(t, false)
	h.call(t, "app.init", h.initParams(filepath.Join(h.tmp, "data"))).fails(t, CodeInput, errShutDown.msg)
	h.call(t, "app.info", ``).fails(t, CodeInput, errShutDown.msg)
}

func TestStart_AfterShutdownRace(t *testing.T) {
	// app.shutdown can land between Dispatch's ready check and start.
	s := newServer()
	s.state = stateShutDown
	if _, err := s.start(); err != errShutDown {
		t.Errorf("start = %v", err)
	}
}

func TestInit_DataDirFailsThenRetry(t *testing.T) {
	h := newLC(t)
	file := filepath.Join(h.tmp, "file")
	writeFile(t, file, "x")

	env := h.call(t, "app.init", h.initParams(filepath.Join(file, "sub")))
	env.fails(t, CodeFailed, "")
	if !strings.HasPrefix(env.Error.Message, "Cannot create data directory") {
		t.Errorf("message = %q", env.Error.Message)
	}
	if h.state() != stateNew || h.srv.logger.Load() != nil {
		t.Fatalf("state = %v after failed init", h.state())
	}
	h.call(t, "app.info", ``).fails(t, CodeInput, errNotReady.msg)

	dir := h.init(t)
	if !strings.Contains(readLogIn(t, dir), "RHG Authenticator starting") {
		t.Error("retry did not log in the good dir")
	}
}

func TestInit_ServiceFailsClosesLogsThenRetry(t *testing.T) {
	h := newLC(t)
	var capturedDuring bool
	h.srv.newService = func(service.Config) (*service.App, error) {
		capturedDuring = log.Writer() != os.Stderr
		return nil, errors.New("Cannot start signing service: boom")
	}
	bad := filepath.Join(h.tmp, "bad")
	h.call(t, "app.init", h.initParams(bad)).fails(t, CodeFailed, "Cannot start signing service: boom")
	if !capturedDuring {
		t.Error("stdlib log not captured while the service was created")
	}
	if log.Writer() != os.Stderr {
		t.Error("failed init left the stdlib log captured")
	}
	if h.state() != stateNew {
		t.Fatalf("state = %v after failed init", h.state())
	}
	if !strings.Contains(readLogIn(t, bad), "RHG Authenticator starting") {
		t.Error("first attempt did not open its log")
	}

	h.srv.newService = h.localService
	dir := h.init(t)
	if log.Writer() == os.Stderr {
		t.Error("retry did not capture the stdlib log")
	}
	if !strings.Contains(readLogIn(t, dir), "RHG Authenticator starting") {
		t.Error("retry did not log in its dir")
	}
}

func TestShutdown_DuringInit(t *testing.T) {
	h := newLC(t)
	h.gate, h.entered = make(chan struct{}), make(chan struct{}, 1)
	initDone := goDispatch(h.srv, "app.init", h.initParams(filepath.Join(h.tmp, "data")))
	select {
	case <-h.entered:
	case <-time.After(waitTimeout):
		t.Fatal("registry fetch never started")
	}

	h.wantCanQuit(t, false) // initializing
	for _, m := range gatedMethods() {
		h.call(t, m, ``).fails(t, CodeInput, errNotReady.msg)
	}
	h.call(t, "app.init", ``).fails(t, CodeInput, errInitialized.msg)

	shutDone := goDispatch(h.srv, "app.shutdown", ``)
	select {
	case out := <-shutDone:
		decodeEnvelope(t, "app.shutdown", out).ok(t, nil)
	case <-time.After(waitTimeout):
		t.Fatal("shutdown waited for the registry fetch")
	}
	close(h.gate)

	select {
	case out := <-initDone:
		decodeEnvelope(t, "app.init", out).fails(t, CodeInput, errShutDown.msg)
	case <-time.After(waitTimeout):
		t.Fatal("init never returned")
	}
	h.srv.mu.Lock()
	app, logs := h.srv.app, h.srv.logs
	h.srv.mu.Unlock()
	if h.state() != stateShutDown || app != nil || logs != nil {
		t.Errorf("state = %v, app = %v, logs = %v", h.state(), app, logs)
	}
	if log.Writer() != os.Stderr {
		t.Error("late init did not close its logs")
	}
	h.call(t, "app.init", h.initParams(filepath.Join(h.tmp, "data2"))).fails(t, CodeInput, errShutDown.msg)
}

func TestShutdown_DuringFailingInit(t *testing.T) {
	h := newLC(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.srv.newService = func(service.Config) (*service.App, error) {
		close(entered)
		<-release
		return nil, errors.New("Cannot start signing service: boom")
	}
	initDone := goDispatch(h.srv, "app.init", h.initParams(filepath.Join(h.tmp, "data")))
	waitFor(t, entered, "service creation")
	h.call(t, "app.shutdown", ``).ok(t, nil)
	close(release)
	decodeEnvelope(t, "app.init", waitFor(t, initDone, "app.init returning")).fails(t, CodeFailed, "Cannot start signing service: boom")
	if h.state() != stateShutDown {
		t.Errorf("state = %v, want shut down", h.state())
	}
	h.call(t, "app.init", ``).fails(t, CodeInput, errShutDown.msg)
}

func TestInternalErrorEvent(t *testing.T) {
	h := newLC(t)
	dir := h.init(t)
	safego.Go(func() { panic("background boom") })
	if data := h.sink.wait(t, EventInternalError, 1); string(data) != "null" {
		t.Errorf("app.internalError data = %s", data)
	}
	if !strings.Contains(readLogIn(t, dir), "PANIC (goroutine): background boom") {
		t.Error("panic not logged")
	}
}

func TestUpdate_StatusEvents(t *testing.T) {
	h := newLC(t)
	h.init(t)
	h.startAndSettle(t)

	idle := `{"status":{"state":"idle","version":"","releaseUrl":"","moveToApplications":false},"updated":null}`
	if env := h.call(t, "update.current", ``); string(env.Result) != idle {
		t.Errorf("initial update.current = %s", env.Result)
	}

	const rel = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v9.9.9"
	for i, tc := range []struct {
		st   update.Status
		want string
	}{
		{update.Status{State: update.StateReady, Version: "9.9.9", ReleaseURL: rel},
			`{"state":"ready","version":"9.9.9","releaseUrl":"` + rel + `","moveToApplications":false}`},
		{update.Status{State: update.StateManualOnly, Version: "9.9.9", ReleaseURL: "https://evil.example/x", MoveToApplications: true},
			`{"state":"manualOnly","version":"9.9.9","releaseUrl":"","moveToApplications":true}`},
		{update.Status{State: update.StateIdle},
			`{"state":"idle","version":"","releaseUrl":"","moveToApplications":false}`},
	} {
		h.mgr.cfg.OnStatus(tc.st)
		if got := h.sink.wait(t, EventUpdateStatus, i+1); string(got) != tc.want {
			t.Errorf("update.status = %s, want %s", got, tc.want)
		}
		var cur struct{ Status json.RawMessage }
		h.call(t, "update.current", ``).ok(t, &cur)
		if string(cur.Status) != tc.want {
			t.Errorf("update.current status = %s, want %s", cur.Status, tc.want)
		}
	}
	if got := statusJSON(update.Status{State: update.State(99)}).State; got != "idle" {
		t.Errorf("unknown state maps to %q", got)
	}
}

func TestUpdate_UpdatedNoticeOnce(t *testing.T) {
	const rel = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator/releases/tag/v2.0.0"
	h := newLC(t)
	h.init(t)
	h.startAndSettle(t)
	updated := func() string {
		var cur struct{ Updated json.RawMessage }
		h.call(t, "update.current", ``).ok(t, &cur)
		return string(cur.Updated)
	}

	// Emitted first: a later pull gets nothing.
	h.mgr.cfg.OnUpdated("2.0.0", rel)
	if got := string(h.sink.wait(t, EventUpdateUpdated, 1)); got != `{"version":"2.0.0","releaseUrl":"`+rel+`"}` {
		t.Errorf("update.updated = %s", got)
	}
	if got := updated(); got != "null" {
		t.Errorf("pull after emit = %s", got)
	}

	// No callback: the notice waits for one pull, then is gone.
	h.srv.events.SetSink(nil)
	h.mgr.cfg.OnUpdated("2.0.0", "http://github.com/x")
	h.srv.events.SetSink(h.sink.add)
	if got := updated(); got != `{"version":"2.0.0","releaseUrl":""}` {
		t.Errorf("first pull = %s", got)
	}
	if got := updated(); got != "null" {
		t.Errorf("second pull = %s", got)
	}
	if n := len(h.sink.named(t, EventUpdateUpdated)); n != 1 {
		t.Errorf("update.updated emitted %d times", n)
	}
}

func TestPackageEntryPoints(t *testing.T) {
	sink := newEventSink()
	SetEventCallback(sink.add)
	if !defaultServer.events.attached() {
		t.Error("SetEventCallback did not attach")
	}
	if got := string(Dispatch("app.canQuit", nil)); got != `{"ok":true,"result":{"dirty":false}}` {
		t.Errorf("app.canQuit = %s", got)
	}
	if got := string(Dispatch("app.info", nil)); !strings.Contains(got, `"code":"input"`) {
		t.Errorf("app.info before init = %s", got)
	}
	SetEventCallback(nil)
	if defaultServer.events.attached() {
		t.Error("SetEventCallback(nil) did not detach")
	}
}

func TestNewServer_ProductionDeps(t *testing.T) {
	if buildinfo.FakeBuild {
		t.Skip("the rhgfake build replaces the production dependencies (TestFakeBuild_Defaults)")
	}
	s := newServer()
	if s.newKeyring() == nil || s.newService == nil {
		t.Error("missing keyring or service constructor")
	}
	if _, ok := s.newManager(update.Config{DataDir: t.TempDir()}).(*update.Manager); !ok {
		t.Error("newManager does not build an *update.Manager")
	}
	if s.state != stateNew || s.events.attached() {
		t.Error("new server not in stateNew without a callback")
	}
}

func TestInit_PanicReturnsToNew(t *testing.T) {
	h := newLC(t)
	h.srv.newService = func(service.Config) (*service.App, error) { panic("service construction failed") }
	bad := filepath.Join(h.tmp, "bad")
	h.call(t, "app.init", h.initParams(bad)).fails(t, CodeInternal, msgInternal)
	if !strings.Contains(readLogIn(t, bad), "rpc: panic in app.init: string") {
		t.Error("the init panic was not logged")
	}
	if h.state() != stateNew {
		t.Fatalf("state = %v after a panicking init, want new", h.state())
	}
	if log.Writer() != os.Stderr {
		t.Error("a panicking init left the stdlib log captured")
	}
	h.srv.newService = h.localService
	h.init(t)
}

// exportErrorLog runs app.exportErrorLog to path.
func (h *lcHarness) exportErrorLog(t testing.TB, path string) envelope {
	t.Helper()
	return h.call(t, "app.exportErrorLog", `{"path":`+jsonString(path)+`}`)
}

// wantExported asserts that app.exportErrorLog saves the diagnostic log,
// which app.init opened in dir, to a new file outside it.
func (h *lcHarness) wantExported(t testing.TB, dir string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "error-log.txt")
	var notice service.ExportResult
	h.exportErrorLog(t, target).ok(t, &notice)
	if notice != service.ErrorLogExported(target) {
		t.Errorf("export notice = %+v", notice)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "RHG Authenticator starting") || !strings.HasPrefix(readLogIn(t, dir), string(data)) {
		t.Errorf("exported %q, not the diagnostic log in %s", data, dir)
	}
}

// wantNotExported asserts that app.exportErrorLog is refused as not
// initialized and writes nothing.
func (h *lcHarness) wantNotExported(t testing.TB) {
	t.Helper()
	target := filepath.Join(h.tmp, "error-log.txt")
	h.exportErrorLog(t, target).fails(t, CodeInput, errNotReady.msg)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("target written: %v", err)
	}
}

func TestExportErrorLog_BeforeInit(t *testing.T) {
	h := newLC(t)
	h.wantNotExported(t)
	h.call(t, "app.exportErrorLog", `{"path":"/x","y":1}`).fails(t, CodeInput, msgBadParams)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	h.wantNotExported(t) // shut down before any init: still no data folder
}

func TestExportErrorLog_DataDirFailed(t *testing.T) {
	h := newLC(t)
	file := filepath.Join(h.tmp, "file")
	writeFile(t, file, "x")
	h.call(t, "app.init", h.initParams(filepath.Join(file, "sub"))).fails(t, CodeFailed, "")
	h.wantNotExported(t)
}

func TestExportErrorLog_DuringInit(t *testing.T) {
	h := newLC(t)
	h.gate, h.entered = make(chan struct{}), make(chan struct{}, 1)
	release := sync.OnceFunc(func() { close(h.gate) })
	t.Cleanup(release) // a failed assertion must not leave the fetch blocked
	dir := filepath.Join(h.tmp, "data")
	initDone := goDispatch(h.srv, "app.init", h.initParams(dir))
	waitFor(t, h.entered, "registry fetch")
	if h.state() != stateInitializing {
		t.Fatalf("state = %v, want initializing", h.state())
	}
	h.wantExported(t, dir)
	h.exportErrorLog(t, filepath.Join(dir, "x.txt")).fails(t, CodeFailed, protectedPathMsg)
	release()
	decodeEnvelope(t, "app.init", waitFor(t, initDone, "app.init returning")).ok(t, nil)
	h.wantExported(t, dir)
}

func TestExportErrorLog_AfterFailedInit(t *testing.T) {
	h := newLC(t)
	h.srv.newService = func(service.Config) (*service.App, error) {
		return nil, errors.New("Cannot start signing service: boom")
	}
	bad := filepath.Join(h.tmp, "bad")
	h.call(t, "app.init", h.initParams(bad)).fails(t, CodeFailed, "Cannot start signing service: boom")
	if h.state() != stateNew {
		t.Fatalf("state = %v after failed init", h.state())
	}
	h.wantExported(t, bad)

	for _, target := range []string{filepath.Join(bad, debuglog.FileName), filepath.Join(bad, "x.txt")} {
		h.exportErrorLog(t, target).fails(t, CodeFailed, protectedPathMsg)
	}
	if _, err := os.Stat(filepath.Join(bad, "x.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("protected target written: %v", err)
	}
	h.exportErrorLog(t, "error-log.txt").fails(t, CodeFailed, "Choose a file to save to.")

	// A retry replaces the data folder: the old one is no longer protected.
	h.srv.newService = h.localService
	dir := h.init(t)
	h.wantExported(t, dir)
	h.exportErrorLog(t, filepath.Join(dir, "x.txt")).fails(t, CodeFailed, protectedPathMsg)
	h.exportErrorLog(t, filepath.Join(bad, "x.txt")).ok(t, nil)
}

func TestExportErrorLog_AfterShutdown(t *testing.T) {
	h := newLC(t)
	dir := h.init(t)
	h.startAndSettle(t)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	h.wantExported(t, dir)
	h.exportErrorLog(t, filepath.Join(dir, "x.txt")).fails(t, CodeFailed, protectedPathMsg)
}

func TestExportErrorLog_AfterShutdownDuringFailingInit(t *testing.T) {
	h := newLC(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.srv.newService = func(service.Config) (*service.App, error) {
		close(entered)
		<-release
		return nil, errors.New("Cannot start signing service: boom")
	}
	dir := filepath.Join(h.tmp, "data")
	initDone := goDispatch(h.srv, "app.init", h.initParams(dir))
	waitFor(t, entered, "service creation")
	h.call(t, "app.shutdown", ``).ok(t, nil)
	close(release)
	decodeEnvelope(t, "app.init", waitFor(t, initDone, "app.init returning")).fails(t, CodeFailed, "")
	h.wantExported(t, dir)
}
