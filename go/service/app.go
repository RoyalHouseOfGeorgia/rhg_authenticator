// Package service holds the signing, bulk, PIN, YubiKey, GitHub login and
// registry-editing logic behind the RHG Authenticator user interfaces. App is
// the entry point.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// Sentinel errors returned by App methods.
var (
	// ErrBusy is returned when a conflicting operation is already running
	// (see App for the three groups).
	ErrBusy = errors.New("another operation is in progress")
	// ErrNoBulkPlan is returned when no bulk file has been loaded.
	ErrNoBulkPlan = errors.New("no bulk file loaded")
	// ErrNotLoggedIn is returned by SubmitRegistry when there is no usable
	// GitHub session (logged out or offline).
	ErrNotLoggedIn = errors.New("not logged in to GitHub")
)

// Prompter asks the operator for the YubiKey PIN.
type Prompter interface {
	// RequestPIN asks the user for the YubiKey PIN. On ctx.Done() the implementation
	// dismisses its UI and returns. An empty pin means the user cancelled.
	RequestPIN(ctx context.Context, rememberDefault bool) (pin string, remember bool, err error)
}

// Events receives progress notifications. Emit may be called from any
// goroutine, including the UI thread (Logout emits synchronously), and must
// not block: the implementation queues onto its UI thread (e.g. fyne.Do, never
// fyne.DoAndWait). A host registers its handlers and then calls App.Start.
type Events interface {
	Emit(name string, payload any)
}

// Event names passed to Events.Emit.
const (
	// EventSignConnecting fires once the PIN is resolved and Sign opens the
	// card. Payload: nil.
	EventSignConnecting = "sign.connecting"
	// EventBulkConnecting fires at most once per RunBulk — only when there are
	// rows to sign and the PIN was resolved — and before any EventBulkProgress.
	// Payload: nil.
	EventBulkConnecting = "bulk.connecting"
	// EventBulkProgress fires before each to_sign row. Payload: BulkProgress.
	EventBulkProgress = "bulk.progress"
	// EventAuthChanged fires after every login-state change. Payload: the
	// AuthState at emit time; overlapping changes can arrive out of order, so a
	// handler that needs the current state calls App.AuthState.
	EventAuthChanged = "auth.changed"
	// EventAuthDeviceCode fires when Login has a code for the user to enter. Payload: DeviceCode.
	EventAuthDeviceCode = "auth.deviceCode"
	// EventRegistryChanged fires after a fetch replaces the edited registry, and
	// after the Start fetch even if it failed (Registry().Loaded then stays false). Payload: nil.
	EventRegistryChanged = "registry.changed"
)

// Config holds the host-provided dependencies of an App.
type Config struct {
	DataDir     string           // app data dir; already created by the host
	Logger      *debuglog.Logger // host-opened diagnostic log
	RegistryURL string
	Keyring     ghapi.Keyring // GitHub token store; nil disables GitHub login and issue reports (then Login, Reconnect and Logout must not be called)
	Prompter    Prompter
	Events      Events
}

// Info is the registry and build information shown in the status bar.
type Info struct {
	Version                     string
	Online                      bool
	ActiveKeys, RecentlyExpired int
}

// SignFields are the operator's sign form inputs.
type SignFields struct{ Recipient, Honor, Detail, Date string }

// SignResult is a successful Sign. The text fields are what was signed
// (trimmed and NFC-normalized).
type SignResult struct {
	Recipient, Honor, Detail, Date, URL, Hash8 string
	Existing                                   bool
	PNGPreview                                 []byte
}

// SignError is a failed Sign. Message is the user-facing status text ("" for a cancel).
type SignError struct {
	Message     string
	OfferReport bool
	Err         error
}

func (e *SignError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Err.Error()
}

func (e *SignError) Unwrap() error { return e.Err }

// BulkPlan describes a loaded bulk file for the confirm step.
type BulkPlan struct {
	ToSign                     int
	CountsLine                 string
	PreviewNames, InvalidLines []string
}

// BulkOutcome summarizes a finished bulk run. The invalid rows are the
// BulkPlan's InvalidLines; a run never changes them.
type BulkOutcome struct{ SummaryLine, StopMessage string }

// BulkProgress is the EventBulkProgress payload.
type BulkProgress struct {
	Done, Total int
	Name        string
}

// KeyCheck is the user-facing result of a YubiKey registry check.
type KeyCheck struct {
	Status  string
	Details []string
}

// App owns the signing, GitHub login and registry-editing state and rules
// behind the user interface. Info, Honors, LogPath, DebugLogPath, CancelBulk,
// AuthState, CancelLogin, GitHubClient, Registry, AddEntry, UpdateEntry,
// Dirty, Start and Close never block, and SaveQR, Logout and ImportCertificate
// do only quick local file or keyring I/O, so these may be called on a UI
// thread; every other method may block on file, card or network I/O or the
// PIN prompt and must not be called on a UI thread. ErrBusy comes from three independent
// guards: Sign, LoadBulk, RunBulk, ExportBulkResults, CheckYubiKey and
// ImportFromYubiKey while another of them runs; Login and Reconnect while
// either runs; SubmitRegistry while another submit runs.
type App struct {
	dataDir     string
	logPath     string
	logger      *debuglog.Logger
	registryURL string
	keyring     ghapi.Keyring
	prompter    Prompter
	events      Events
	reg         core.Registry // signing registry: fetched once by New, never changed (read without mu)
	online      bool
	pinCache    *yubikey.PinCache

	pinTimeout        time.Duration
	openAdapter       func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error)
	restoreSession    func(ctx context.Context, kr ghapi.Keyring, configDir string) (ghapi.Token, string, bool, bool, error)
	requestDeviceCode func(ctx context.Context) (ghapi.DeviceCodeResponse, error)
	pollForToken      func(ctx context.Context, deviceCode string, interval, expiresIn int) (ghapi.Token, error)
	validateToken     func(ctx context.Context, tok ghapi.Token) (string, error)
	newClient         func(token string) *ghapi.Client

	busy       atomic.Bool
	loggingIn  atomic.Bool
	submitting atomic.Bool

	mu          sync.Mutex // guards the fields below
	plan        []bulk.Result
	bulkCancel  context.CancelFunc
	loginCancel context.CancelFunc
	token       ghapi.Token
	loggedIn    bool
	offline     bool
	githubUser  string
	edit        core.Registry // the copy being edited; replaced by FetchRegistry
	dirty       bool
	// baseBytes is the marshalRegistry output of edit as last fetched; nil =
	// not loaded. SubmitRegistry refuses unless main still matches it.
	baseBytes []byte
}

// New cleans stale issuance-log temp files, fetches the registry (offline on
// failure) and returns a ready App. Call Start once the UI listens for events.
// New blocks for up to registry.FetchTimeout on the network, so the host calls
// it before its UI loop starts, never from a UI callback.
func New(cfg Config) (*App, error) {
	if cfg.DataDir == "" || cfg.Prompter == nil || cfg.Events == nil {
		return nil, errors.New("service: DataDir, Prompter and Events are required")
	}
	logger := cfg.Logger
	logPath := filepath.Join(cfg.DataDir, "issuances.json")
	if err := issuancelog.CleanStaleTmpFiles(logPath); err != nil {
		logger.Logf("warning: log cleanup failed: %s", core.SanitizeForLog(err.Error()))
	}

	// Remote only — no cache or embedded fallback.
	reg, err := registry.FetchRegistry(cfg.RegistryURL)
	online := err == nil
	if !online {
		logger.Logf("warning: registry fetch failed: %s", core.SanitizeForLog(err.Error()))
		reg = core.Registry{}
	}
	logger.Logf("registry fetch: online=%v", online)

	a := &App{
		dataDir:     cfg.DataDir,
		logPath:     logPath,
		logger:      logger,
		registryURL: cfg.RegistryURL,
		keyring:     cfg.Keyring,
		prompter:    cfg.Prompter,
		events:      cfg.Events,
		reg:         reg,
		online:      online,
		pinCache:    yubikey.NewPinCache(),
		pinTimeout:  defaultPINEntryTimeout,
		openAdapter: func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
			a, err := yubikey.NewYubiKeyAdapter(readPin)
			if err != nil {
				return nil, nil, err
			}
			return a, a, nil
		},
		restoreSession:    ghapi.RestoreSession,
		requestDeviceCode: ghapi.RequestDeviceCode,
		pollForToken:      ghapi.PollForToken,
		validateToken:     ghapi.ValidateToken,
		newClient:         ghapi.NewClient,
	}
	return a, nil
}

// Start restores the saved GitHub session (with a keyring) in the background
// and then loads the registry for editing, emitting EventAuthChanged and
// EventRegistryChanged. Hosts call it once, after registering event handlers.
func (a *App) Start() {
	safego.Go(a.startupRestore)
}

// LogPath returns the issuance log path.
func (a *App) LogPath() string { return a.logPath }

// DebugLogPath returns the diagnostic log path (for "Export Error Log").
func (a *App) DebugLogPath() string { return a.logger.Path() }

// Info returns the build version and registry statistics.
func (a *App) Info() Info {
	stats := computeRegistryStats(a.reg, time.Now().UTC().Format("2006-01-02"))
	return Info{
		Version:         buildinfo.Version,
		Online:          a.online,
		ActiveKeys:      stats.ActiveKeys,
		RecentlyExpired: stats.RecentlyExpired,
	}
}

// Honors returns the selectable honor titles.
func (a *App) Honors() []string { return append([]string(nil), honorTitles...) }

// request returns f with each field trimmed as the form is signed.
func (f SignFields) request() core.SignRequest {
	return core.SignRequest{
		Recipient: core.TrimJS(f.Recipient),
		Honor:     core.TrimJS(f.Honor),
		Detail:    core.TrimJS(f.Detail),
		Date:      core.TrimJS(f.Date),
	}
}

// Validate reports the first missing or invalid field, with the message shown
// to the user. Sign runs the same check; a UI can call it first to reject a
// form without starting a signing operation.
func (f SignFields) Validate() error {
	req := f.request()
	return validateSignForm(req.Recipient, req.Honor, req.Detail, req.Date)
}

// Sign validates f, prompts for the PIN if needed, and signs and logs the
// credential. A failure is a *SignError, except ErrBusy.
func (a *App) Sign(ctx context.Context, f SignFields) (SignResult, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return SignResult{}, ErrBusy
	}
	defer a.busy.Store(false)

	if err := f.Validate(); err != nil {
		return SignResult{}, &SignError{Message: err.Error(), Err: err}
	}
	req := f.request()

	res, err := executeSignFlow(req, a.logPath, a.openAdapter,
		func() (string, error) { return a.readPIN(ctx) },
		func() { a.events.Emit(EventSignConnecting, nil) },
		a.logger)
	if err != nil {
		clearPINCacheOnAuthError(err, a.pinCache)
		return SignResult{}, &SignError{
			Message:     signFlowErrorMessage(err, a.logger),
			OfferReport: offerIssueReport(err) && a.keyring != nil,
			Err:         err,
		}
	}

	return SignResult{
		Recipient:  norm.NFC.String(req.Recipient),
		Honor:      norm.NFC.String(req.Honor),
		Detail:     norm.NFC.String(req.Detail),
		Date:       req.Date,
		URL:        res.Response.URL,
		Hash8:      res.Hash8,
		Existing:   res.Existing,
		PNGPreview: res.PNGPreview,
	}, nil
}

// readPIN returns the cached PIN or prompts for one, applying the remember
// choice before caching.
func (a *App) readPIN(ctx context.Context) (string, error) {
	if pin, ok := a.pinCache.Get(); ok {
		return pin, nil
	}
	pctx, cancel := context.WithTimeout(ctx, a.pinTimeout)
	defer cancel()
	pin, remember, err := a.prompter.RequestPIN(pctx, a.pinCache.Enabled())
	// The caller's ctx is checked first: its cancellation also ends pctx.
	switch {
	case ctx.Err() != nil:
		return "", errSigningCancelled
	case pctx.Err() != nil:
		return "", errPINEntryTimedOut
	case err != nil:
		return "", err
	case pin == "":
		return "", errSigningCancelled
	}
	a.pinCache.SetEnabled(remember)
	return processPINResult(pin, a.pinCache)
}

// SaveQR writes the QR code for url (a SignResult.URL) to path as "svg" or "png".
func (a *App) SaveQR(url, format, path string) error {
	var data []byte
	var err error
	switch format {
	case "svg":
		data, err = qr.GenerateSVG(url)
	case "png":
		data, err = qr.GeneratePNG(url, qrSavePx)
	default:
		return fmt.Errorf("unsupported QR format %q", format)
	}
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		a.logger.Log(strings.ToUpper(format) + " save failed: " + core.SanitizeForLog(err.Error()))
	}
	return err
}

// errNotReportable is returned by ReportSignError for an error whose
// OfferReport is false.
var errNotReportable = errors.New("this error is not reportable")

// ReportSignError files a GitHub issue for se, a Sign failure with
// OfferReport set, and returns its https://github.com URL ("" if the result
// is not a GitHub URL).
func (a *App) ReportSignError(ctx context.Context, se *SignError) (string, error) {
	if se == nil || !se.OfferReport || a.keyring == nil {
		return "", errNotReportable
	}
	title := errorreport.BuildIssueTitle("signing", se.Message)
	body := signIssueBody(se.Err, se.Message)
	resultURL, err := errorreport.ReportIssue(ctx, a.keyring, a.dataDir, title, body)
	if resultURL != "" && ghapi.ParseGitHubURL(resultURL) == nil {
		a.logger.Log("Report Issue: refusing to open non-GitHub URL: " + core.SanitizeForLog(resultURL))
		return "", err
	}
	return resultURL, err
}

// LoadBulk reads and plans the bulk CSV at path, storing it for RunBulk.
func (a *App) LoadBulk(path string) (BulkPlan, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return BulkPlan{}, ErrBusy
	}
	defer a.busy.Store(false)

	f, err := os.Open(path)
	if err != nil {
		return BulkPlan{}, err
	}
	defer f.Close()
	results, err := loadBulkPlan(f, a.logPath)
	a.mu.Lock()
	a.plan = results
	a.mu.Unlock()
	if err != nil {
		return BulkPlan{}, err
	}
	counts, preview, invalid := bulkConfirmText(results)
	return BulkPlan{
		ToSign:       bulk.Summarize(results).ToSign,
		CountsLine:   counts,
		PreviewNames: preview,
		InvalidLines: invalid,
	}, nil
}

// RunBulk signs the loaded plan's to_sign rows. A flow failure is reported
// only through BulkOutcome.StopMessage.
func (a *App) RunBulk(ctx context.Context) (BulkOutcome, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return BulkOutcome{}, ErrBusy
	}
	defer a.busy.Store(false)

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.mu.Lock()
	results := a.plan
	if results != nil {
		a.bulkCancel = cancel
	}
	a.mu.Unlock()
	if results == nil {
		return BulkOutcome{}, ErrNoBulkPlan
	}
	defer func() {
		a.mu.Lock()
		a.bulkCancel = nil
		a.mu.Unlock()
	}()

	err := runBulkFlow(cctx, results, a.logPath, a.openAdapter,
		func() (string, error) { return a.readPIN(cctx) },
		func() { a.events.Emit(EventBulkConnecting, nil) },
		func(done, total int, name string) {
			a.events.Emit(EventBulkProgress, BulkProgress{Done: done, Total: total, Name: name})
		},
		a.logger)
	clearPINCacheOnAuthError(err, a.pinCache)

	return BulkOutcome{
		SummaryLine: bulkSummaryLine(bulk.Summarize(results)),
		StopMessage: bulkStopMessage(err, a.logger),
	}, nil
}

// CancelBulk stops a running bulk batch after its current row.
func (a *App) CancelBulk() {
	a.mu.Lock()
	cancel := a.bulkCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ExportBulkResults writes the loaded plan's per-row results as CSV to path.
func (a *App) ExportBulkResults(path string) error {
	if !a.busy.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer a.busy.Store(false)

	a.mu.Lock()
	results := a.plan
	a.mu.Unlock()
	if results == nil {
		return ErrNoBulkPlan
	}
	if err := saveBulkResults(path, results); err != nil {
		a.logger.Log("bulk results save failed: " + core.SanitizeForLog(err.Error()))
		return err
	}
	return nil
}

// CheckYubiKey reads the inserted key and looks it up in the registry.
func (a *App) CheckYubiKey() (KeyCheck, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return KeyCheck{}, ErrBusy
	}
	defer a.busy.Store(false)

	var res keyCheckResult
	if pub, err := a.readPublicKey(); err != nil {
		res = keyCheckResult{Error: fmt.Errorf("yubikey: %w", err)}
	} else {
		res = checkYubiKey(a.reg, pub)
	}
	if res.Error != nil {
		a.logger.Log("yubikey check: " + core.SanitizeForLog(res.Error.Error()))
	}
	status, details := formatKeyResult(res)
	return KeyCheck{Status: status, Details: details}, nil
}

// Close cancels a running bulk batch and login and wipes the PIN cache.
func (a *App) Close() {
	a.CancelBulk()
	a.CancelLogin()
	a.pinCache.Close()
}
