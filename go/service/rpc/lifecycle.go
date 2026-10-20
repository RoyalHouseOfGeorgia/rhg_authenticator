package rpc

import (
	"context"
	"path/filepath"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/host"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// Fixed messages for calls rejected by the lifecycle.
var (
	errNotReady    = &inputError{"The app is not initialized."}
	errShutDown    = &inputError{"The app has shut down."}
	errInitialized = &inputError{"The app is already initialized."}
	errStarted     = &inputError{"The app is already started."}
	errNoCallback  = &inputError{"Set the event callback before initializing the app."}
	errBadDataDir  = &inputError{"The data directory must be an absolute path."}
)

type (
	initParams struct {
		DataDir string `json:"dataDir"`
	}
	shutdownParams struct {
		Relaunch bool `json:"relaunch"`
	}
	pinSubmitParams struct {
		RequestID uint64 `json:"requestId"`
		PIN       string `json:"pin"`
		Remember  bool   `json:"remember"`
	}
	pinCancelParams struct {
		RequestID uint64 `json:"requestId"`
	}
)

type canQuitResult struct {
	Dirty bool `json:"dirty"`
}

// requireReady returns the input error for a call that needs stateReady.
func (s *server) requireReady() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case stateReady:
		return nil
	case stateShutDown:
		return errShutDown
	default:
		return errNotReady
	}
}

// initApp moves new → initializing → ready: it resolves the data dir, opens
// the diagnostic log there and creates the App (which fetches the registry).
// The state lock is not held meanwhile, so app.shutdown can win; init then
// closes what it opened. A failure, or a panic, returns to stateNew so the
// host may retry.
func (s *server) initApp(p initParams) (any, error) {
	if p.DataDir != "" && !filepath.IsAbs(p.DataDir) {
		return nil, errBadDataDir
	}
	s.mu.Lock()
	switch {
	case s.state == stateShutDown:
		s.mu.Unlock()
		return nil, errShutDown
	case s.state != stateNew:
		s.mu.Unlock()
		return nil, errInitialized
	case !s.events.attached():
		s.mu.Unlock()
		return nil, errNoCallback
	}
	s.state = stateInitializing
	s.mu.Unlock()

	// Until init settles, any exit — an error or a panic — closes the logs it
	// opened and returns to stateNew (unless a shutdown won).
	var logs *host.Logs
	settled := false
	defer func() {
		if settled {
			return
		}
		if logs != nil {
			logs.Close()
		}
		s.initFailed()
	}()

	dir, err := host.DataDir(p.DataDir)
	if err != nil {
		return nil, err
	}
	logs = host.OpenLogs(dir, func() { s.events.Emit(EventInternalError, nil) })
	s.setLogs(dir, logs)
	svc, err := s.newService(service.Config{
		DataDir:  dir,
		Logger:   logs.Logger,
		Keyring:  s.newKeyring(),
		Prompter: s.pins,
		Events:   s.events,
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.state != stateInitializing {
		s.mu.Unlock()
		svc.Close()
		return nil, errShutDown
	}
	s.app, s.logs, s.state = svc, logs, stateReady
	s.mu.Unlock()
	settled = true
	return svc.Info(), nil
}

// setLogs records dir as the data folder and makes logs' logger the server's
// and its jsonEvents' diagnostic log, together under mu so app.exportErrorLog
// never pairs one init's folder with another's log.
func (s *server) setLogs(dir string, logs *host.Logs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataDir = dir
	s.logger.Store(logs.Logger)
	s.events.logger.Store(logs.Logger)
}

// initFailed returns a failed init to stateNew, unless a shutdown happened
// meanwhile. The logger and data folder stay set (the logger writes by path,
// so it still works after Logs.Close) and a retry replaces them, so a panic
// that failed the init is still logged by Dispatch and the error log can
// still be exported.
func (s *server) initFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stateInitializing {
		s.state = stateNew
	}
}

// start starts the App's background work and the update manager, once.
func (s *server) start() (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateReady {
		return nil, errShutDown // app.shutdown won since Dispatch checked
	}
	if s.started {
		return nil, errStarted
	}
	s.started = true
	cfg := host.UpdateConfig(s.dataDir)
	cfg.OnStatus = s.onUpdateStatus
	cfg.OnUpdated = s.onUpdated
	cfg.Logf = s.logger.Load().Logf
	ctx, cancel := context.WithCancel(context.Background())
	manager := s.newManager(cfg)
	s.manager, s.cancel = manager, cancel
	// Neither blocks: both only launch goroutines.
	s.app.Start()
	safego.Go(func() { manager.Run(ctx) })
	return struct{}{}, nil
}

// canQuit reports whether the App has unsubmitted registry changes; false
// outside stateReady.
func (s *server) canQuit() (any, error) {
	s.mu.Lock()
	var app *service.App
	if s.state == stateReady {
		app = s.app
	}
	s.mu.Unlock()
	return canQuitResult{Dirty: app != nil && app.Dirty()}, nil
}

// exportErrorLog saves the diagnostic log to p.Path in any state once an
// app.init has opened it: while that init still runs (it can wait long on the
// registry fetch), after it failed, and after app.shutdown, which leaves the
// log open. It never touches the App, which may not exist. Before any init
// got that far it returns errNotReady.
func (s *server) exportErrorLog(p pathParams) (any, error) {
	s.mu.Lock()
	dir := s.dataDir
	logger := s.logger.Load()
	s.mu.Unlock()
	if dir == "" || logger == nil {
		return nil, errNotReady
	}
	return void(service.ExportErrorLog(dir, logger, p.Path))
}

// shutdown moves to stateShutDown from any state, once: it cancels a pending
// PIN prompt (emitting pin.dismiss), detaches the event callback, closes the
// App, stops the update manager and installs a Ready update (relaunching if
// asked). It does not wait for an app.init in progress, and leaves the
// diagnostic log open for the rest of the process; an app.init it outran
// closes the logs it opened (crash output, stdlib capture) when it returns,
// while app.exportErrorLog still reads the log by path.
func (s *server) shutdown(p shutdownParams) (any, error) {
	s.mu.Lock()
	if s.state == stateShutDown {
		s.mu.Unlock()
		return struct{}{}, nil
	}
	s.state = stateShutDown
	app, manager, cancel := s.app, s.manager, s.cancel
	s.mu.Unlock()

	s.pins.shutdown()
	s.events.SetSink(nil)
	if app != nil {
		app.Close()
	}
	if cancel != nil {
		cancel()
	}
	if manager != nil {
		manager.ApplyIfReady(p.Relaunch)
	}
	return struct{}{}, nil
}

// updateState is the latest update offer and the undelivered "updated"
// notice.
type updateState struct {
	status  update.Status
	updated *updatedNotice // nil once delivered (or before any)
}

// updateStatus is the JSON form of an update.Status. ReleaseURL is "" unless
// an https://github.com URL.
type updateStatus struct {
	State              string `json:"state"`
	Version            string `json:"version"`
	ReleaseURL         string `json:"releaseUrl"`
	MoveToApplications bool   `json:"moveToApplications"`
}

// updatedNotice is the "updated to version" notice. ReleaseURL is "" unless
// an https://github.com URL.
type updatedNotice struct {
	Version    string `json:"version"`
	ReleaseURL string `json:"releaseUrl"`
}

type updateCurrentResult struct {
	Status  updateStatus   `json:"status"`
	Updated *updatedNotice `json:"updated"`
}

func statusJSON(st update.Status) updateStatus {
	state := "idle"
	switch st.State {
	case update.StateReady:
		state = "ready"
	case update.StateManualOnly:
		state = "manualOnly"
	}
	return updateStatus{
		State:              state,
		Version:            st.Version,
		ReleaseURL:         ghapi.GitHubURLOrEmpty(st.ReleaseURL),
		MoveToApplications: st.MoveToApplications,
	}
}

// onUpdateStatus is the update manager's OnStatus.
func (s *server) onUpdateStatus(st update.Status) {
	s.mu.Lock()
	s.update.status = st
	s.mu.Unlock()
	s.events.Emit(EventUpdateStatus, statusJSON(st))
}

// onUpdated is the update manager's OnUpdated (called at most once). With an
// event callback attached the notice is emitted; otherwise it waits for
// update.current. A callback detached between the check and the emit loses
// it, which only app.shutdown does.
func (s *server) onUpdated(version, releaseURL string) {
	n := &updatedNotice{Version: version, ReleaseURL: ghapi.GitHubURLOrEmpty(releaseURL)}
	if !s.events.attached() {
		s.mu.Lock()
		s.update.updated = n
		s.mu.Unlock()
		return
	}
	s.events.Emit(EventUpdateUpdated, n)
}

// updateCurrent returns the latest update status and the "updated" notice if
// not yet delivered, which it delivers.
func (s *server) updateCurrent() (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := updateCurrentResult{Status: statusJSON(s.update.status), Updated: s.update.updated}
	s.update.updated = nil
	return res, nil
}
