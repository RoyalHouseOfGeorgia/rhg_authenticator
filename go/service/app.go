// Package service holds the signing, bulk, PIN, YubiKey, GitHub login,
// registry-editing, issuance-history, revocation, registry-audit and
// log-export logic behind the RHG Authenticator user interfaces. App is the
// entry point.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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

// Sentinel errors returned by App methods. Like every error an App method
// returns, their text is user-facing; a method may return one wrapped behind
// its own message, so callers match them with errors.Is.
var (
	// ErrBusy is returned when a conflicting operation is already running
	// (see App for the guard groups).
	ErrBusy = errors.New("Another operation is in progress.")
	// ErrNoBulkPlan is returned when no bulk file has been loaded.
	ErrNoBulkPlan = errors.New("No bulk file loaded.")
	// ErrNotLoggedIn is returned by SubmitRegistry and Revoke when there is no
	// usable GitHub session (logged out or offline).
	ErrNotLoggedIn = errors.New("Not logged in to GitHub.")
	// ErrSessionExpired is matched by a SubmitRegistry or Revoke error when
	// GitHub rejected the session (HTTP 401); the App has then logged out.
	ErrSessionExpired = errors.New("Your GitHub session expired. Please log in again.")
	// ErrNotFound is matched by a ReportSignError error when the report id is
	// unknown or no longer the latest reportable failure.
	ErrNotFound = errors.New("The requested item was not found.")
)

// reportTimeout bounds ReportSignError's GitHub calls.
const reportTimeout = 30 * time.Second

// userError is an error whose text is the user-facing msg, wrapping the
// sentinels and causes in errs so errors.Is and errors.As still match them.
type userError struct {
	msg  string
	errs []error
}

func (e *userError) Error() string   { return e.msg }
func (e *userError) Unwrap() []error { return e.errs }

// userErr returns an error with the user-facing text msg that wraps errs.
func userErr(msg string, errs ...error) error {
	return &userError{msg: msg, errs: errs}
}

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
	// EventHistoryChanged fires after RefreshHistory, RemoveDuplicates, a Sign
	// that wrote a new record, or a RunBulk that signed any row re-reads the
	// issuance log, even if the read failed
	// (HistorySnapshot.LoadFailed). The records may have changed, so a UI
	// resets its selection. Payload: nil.
	EventHistoryChanged = "history.changed"
	// EventRevocationsChanged fires when a RefreshHistory revocation-list fetch
	// finishes, whether or not it succeeded
	// (HistorySnapshot.RevocationsUnavailable). The records are unchanged, so a
	// UI keeps its selection. Payload: nil.
	EventRevocationsChanged = "history.revocationsChanged"
)

// Config holds the host-provided dependencies of an App.
type Config struct {
	DataDir     string           // app data dir; already created by the host
	Logger      *debuglog.Logger // host-opened diagnostic log
	RegistryURL string
	// RevocationURL is the published revocation list; empty or unreachable
	// leaves revocations unavailable.
	RevocationURL string
	Keyring       ghapi.Keyring // GitHub token store; nil disables GitHub login (Login then returns ErrLoginUnavailable; Revoke and SubmitRegistry return ErrNotLoggedIn; Report Issue opens the browser form)
	Prompter      Prompter
	Events        Events
}

// Info is the registry and build information shown in the status bar.
type Info struct {
	Version         string `json:"version"`
	Online          bool   `json:"online"`
	ActiveKeys      int    `json:"activeKeys"`
	RecentlyExpired int    `json:"recentlyExpired"`
}

// SignFields are the operator's sign form inputs.
type SignFields struct {
	Recipient string `json:"recipient"`
	Honor     string `json:"honor"`
	Detail    string `json:"detail"`
	Date      string `json:"date"`
}

// SignResult is a successful Sign. The text fields are what was signed
// (trimmed and NFC-normalized). Warning is non-empty when the credential was
// signed but not recorded in the issuance log; the UI shows it instead of a
// plain success. SVGFilename and PNGFilename are the default names for
// saving the QR code with SaveQR.
type SignResult struct {
	Recipient   string `json:"recipient"`
	Honor       string `json:"honor"`
	Detail      string `json:"detail"`
	Date        string `json:"date"`
	URL         string `json:"url"`
	Hash8       string `json:"hash8"`
	Existing    bool   `json:"existing"`
	PNGPreview  []byte `json:"pngPreview"` // base64 in JSON
	Warning     string `json:"warning"`
	SVGFilename string `json:"svgFilename"`
	PNGFilename string `json:"pngFilename"`
}

// SignError is a failed Sign. Message is the user-facing status text.
// ReportID, set only when OfferReport, is the opaque id to pass to
// ReportSignError.
type SignError struct {
	Message     string
	OfferReport bool
	ReportID    string
	Err         error
}

func (e *SignError) Error() string { return e.Message }

func (e *SignError) Unwrap() error { return e.Err }

// BulkPlan describes a loaded bulk file for the confirm step.
type BulkPlan struct {
	ToSign       int      `json:"toSign"`
	CountsLine   string   `json:"countsLine"`
	PreviewNames []string `json:"previewNames"`
	InvalidLines []string `json:"invalidLines"`
}

// BulkStop is why a bulk run ended.
type BulkStop string

// Bulk run endings.
const (
	BulkCompleted BulkStop = "completed" // every to_sign row was attempted
	BulkCancelled BulkStop = "cancelled" // CancelBulk, ctx or the PIN prompt cancelled it
	BulkFailed    BulkStop = "failed"    // a sign-flow error stopped it
)

// BulkOutcome summarizes a finished bulk run. StopMessage is the
// user-facing text for Stopped ("" when BulkCompleted). ResultsFilename is
// the default name for ExportBulkResults, timestamped when the run finished.
// The invalid rows are the BulkPlan's InvalidLines; a run never changes them.
type BulkOutcome struct {
	SummaryLine     string   `json:"summaryLine"`
	StopMessage     string   `json:"stopMessage"`
	Stopped         BulkStop `json:"stopped"`
	ResultsFilename string   `json:"resultsFilename"`
}

// BulkProgress is the EventBulkProgress payload.
type BulkProgress struct {
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Name  string `json:"name"`
}

// ReportResult is a ReportSignError outcome. URL is the filed issue, or a
// pre-filled new-issue form when the issue could not be filed through the API
// (Filed false); it is "" unless an https github.com URL.
type ReportResult struct {
	URL   string `json:"url"`
	Filed bool   `json:"filed"`
}

// KeyCheckResult is the outcome of a YubiKey registry check.
type KeyCheckResult string

// YubiKey registry check outcomes.
const (
	KeyCheckFound    KeyCheckResult = "found"    // the key matches a registry entry valid today
	KeyCheckNotFound KeyCheckResult = "notFound" // the key was read but matches no valid entry
	KeyCheckFailed   KeyCheckResult = "failed"   // the key could not be read (none plugged in, card error)
)

// KeyCheck is the result of a YubiKey registry check. Status and Details are
// the user-facing text for Result.
type KeyCheck struct {
	Result  KeyCheckResult `json:"result"`
	Status  string         `json:"status"`
	Details []string       `json:"details"`
}

// App owns the signing, GitHub login, registry-editing, issuance-history,
// revocation and audit state and rules behind the user interface. Info,
// Honors, LogPath, CancelBulk, AuthState, CancelLogin, Registry, AddEntry,
// UpdateEntry, Dirty, History, Start and Close never block, and SaveQR,
// Logout, ImportCertificate, IssuanceLogExport, ErrorLogExport,
// ExportIssuanceLog, ExportErrorLog, DuplicatePreview and RemoveDuplicates
// do only short local work (file or keyring I/O; SaveQR renders a PNG in
// about 0.1 s), so these may be called on a UI thread; every other method
// may block on file, card or network I/O or the PIN prompt and must not be
// called on a UI thread. ErrBusy comes from independent guards: Sign,
// LoadBulk, RunBulk, ExportBulkResults, CheckYubiKey and ImportFromYubiKey
// while another of them runs; Login while another Login runs; SubmitRegistry
// while another submit runs; Revoke while another Revoke runs; AuditCommits
// while another audit fetch runs; ReportSignError while another report runs.
type App struct {
	dataDir       string
	logPath       string
	logger        *debuglog.Logger
	registryURL   string
	revocationURL string
	keyring       ghapi.Keyring
	prompter      Prompter
	events        Events
	reg           core.Registry // signing registry: fetched once by New, never changed (read without mu)
	online        bool
	pinCache      *yubikey.PinCache

	pinTimeout        time.Duration
	openAdapter       adapterOpener
	restoreSession    func(ctx context.Context, kr ghapi.Keyring, configDir string) (ghapi.Token, string, bool, bool, error)
	requestDeviceCode func(ctx context.Context) (ghapi.DeviceCodeResponse, error)
	pollForToken      func(ctx context.Context, deviceCode string, interval, expiresIn int) (ghapi.Token, error)
	validateToken     func(ctx context.Context, tok ghapi.Token) (string, error)
	newClient         func(token string) *ghapi.Client
	fetchCommits      func(baseURL string, perPage int, etag string) ([]ghapi.RegistryCommit, string, error)
	reportIssue       func(ctx context.Context, client *ghapi.Client, title, body string) (string, bool)

	busy       atomic.Bool
	loggingIn  atomic.Bool
	submitting atomic.Bool
	revoking   atomic.Bool
	auditing   atomic.Bool
	reporting  atomic.Bool
	// refreshingHistory makes an overlapping RefreshHistory skip its
	// revocation fetch.
	refreshingHistory atomic.Bool
	historyLoadMu     sync.Mutex // serializes loadHistory

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
	history   historyState
	audit     auditState
	// lastReport is the latest reportable Sign failure (nil = none); a newer
	// one replaces it. reportSeq numbers them for SignError.ReportID.
	// lastFiled is lastReport's issue once filed through the API (else nil).
	lastReport *SignError
	lastFiled  *ReportResult
	reportSeq  uint64
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
		dataDir:       cfg.DataDir,
		logPath:       logPath,
		logger:        logger,
		registryURL:   cfg.RegistryURL,
		revocationURL: cfg.RevocationURL,
		keyring:       cfg.Keyring,
		prompter:      cfg.Prompter,
		events:        cfg.Events,
		reg:           reg,
		online:        online,
		pinCache:      yubikey.NewPinCache(),
		pinTimeout:    defaultPINEntryTimeout,
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
		fetchCommits:      ghapi.FetchRegistryCommits,
		reportIssue:       errorreport.ReportIssue,
	}
	return a, nil
}

// Start restores the saved GitHub session (with a keyring) in the background
// and then loads the registry for editing, emitting EventAuthChanged and
// EventRegistryChanged; independently it runs RefreshHistory. Hosts call it
// once, after registering event handlers.
func (a *App) Start() {
	safego.Go(a.startupRestore)
	safego.Go(a.RefreshHistory)
}

// LogPath returns the issuance log path.
func (a *App) LogPath() string { return a.logPath }

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
// credential. A failure is a *SignError, except ErrBusy and a cancelled PIN
// prompt, which matches context.Canceled. A reportable failure (OfferReport)
// becomes the one ReportSignError can file, replacing any earlier one. A new
// issuance record reloads the history (EventHistoryChanged).
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
	if errors.Is(err, errSigningCancelled) {
		return SignResult{}, userErr(errSigningCancelled.Error(), context.Canceled, err)
	}
	if err != nil {
		clearPINCacheOnAuthError(err, a.pinCache)
		// A QR failure may follow a newly written record.
		if sfe := (*signFlowError)(nil); errors.As(err, &sfe) && sfe.Phase == phaseQR {
			a.loadHistory()
		}
		se := &SignError{
			Message:     signFlowErrorMessage(err, a.logger),
			OfferReport: offerIssueReport(err),
			Err:         err,
		}
		if se.OfferReport {
			a.mu.Lock()
			a.reportSeq++
			se.ReportID = strconv.FormatUint(a.reportSeq, 10)
			kept := *se
			a.lastReport = &kept
			a.lastFiled = nil
			a.mu.Unlock()
		}
		return SignResult{}, se
	}

	var warning string
	if res.NotLogged {
		warning = msgNotLogged
	} else if !res.Existing {
		a.loadHistory()
	}
	return SignResult{
		Recipient:   norm.NFC.String(req.Recipient),
		Honor:       norm.NFC.String(req.Honor),
		Detail:      norm.NFC.String(req.Detail),
		Date:        req.Date,
		URL:         res.Response.URL,
		Hash8:       res.Hash8,
		Existing:    res.Existing,
		PNGPreview:  res.PNGPreview,
		Warning:     warning,
		SVGFilename: buildFilename(req.Date, res.Hash8, "svg"),
		PNGFilename: buildFilename(req.Date, res.Hash8, "png"),
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
		return errors.New("Unsupported QR format.")
	}
	if err != nil {
		a.logger.Log(strings.ToUpper(format) + " generation failed: " + core.SanitizeForLog(err.Error()))
		return userErr("Could not create the "+strings.ToUpper(format)+" file.", err)
	}
	return a.saveUserFile(path, data)
}

// ReportSignError files a GitHub issue for the Sign failure whose
// SignError.ReportID is reportID. Only the latest reportable failure can be
// reported: an unknown or older id returns an error matching ErrNotFound. It
// files at most one issue per failure: once one is filed through the API,
// later calls return it again. A try that only produced the new-issue form
// can be repeated. It returns ErrBusy while another report runs, and gives
// up on GitHub after reportTimeout.
func (a *App) ReportSignError(ctx context.Context, reportID string) (ReportResult, error) {
	if !a.reporting.CompareAndSwap(false, true) {
		return ReportResult{}, ErrBusy
	}
	defer a.reporting.Store(false)
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()

	a.mu.Lock()
	var se SignError
	found := reportID != "" && a.lastReport != nil && a.lastReport.ReportID == reportID
	filed := a.lastFiled
	if found {
		se = *a.lastReport
	}
	a.mu.Unlock()
	switch {
	case !found:
		return ReportResult{}, userErr("This failure can no longer be reported.", ErrNotFound)
	case filed != nil:
		return *filed, nil
	}
	title := errorreport.BuildIssueTitle("signing", se.Message)
	body := signIssueBody(se.Err, se.Message)
	rawURL, apiFiled := a.reportIssue(ctx, a.githubClient(), title, body)
	// A filed issue stays filed (no duplicates); only a bad link is dropped.
	resultURL := ghapi.GitHubURLOrEmpty(rawURL)
	if resultURL == "" && rawURL != "" {
		a.logger.Log("Report Issue: refusing to open non-GitHub URL: " + core.SanitizeForLog(rawURL))
	}
	res := ReportResult{URL: resultURL, Filed: apiFiled}
	if res.Filed {
		a.mu.Lock()
		if a.lastReport != nil && a.lastReport.ReportID == reportID {
			a.lastFiled = &res
		}
		a.mu.Unlock()
	}
	return res, nil
}

// LoadBulk reads and plans the bulk CSV at path, storing it for RunBulk. It
// returns ErrBusy while another card operation runs; other errors are
// logged, wrap their cause, and their text is user-facing.
func (a *App) LoadBulk(path string) (BulkPlan, error) {
	if !a.busy.CompareAndSwap(false, true) {
		return BulkPlan{}, ErrBusy
	}
	defer a.busy.Store(false)

	// A failed load leaves no plan, so RunBulk never signs an earlier file.
	a.mu.Lock()
	a.plan = nil
	a.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		a.logger.Log("bulk load: " + core.SanitizeForLog(err.Error()))
		return BulkPlan{}, userErr("Could not open the CSV file.", err)
	}
	defer f.Close()
	results, err := loadBulkPlan(f, a.logPath, a.logger)
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
	if bulk.Summarize(results).Signed > 0 {
		a.loadHistory()
	}

	stop := bulkStop(err)
	return BulkOutcome{
		SummaryLine:     bulkSummaryLine(bulk.Summarize(results)),
		StopMessage:     bulkStopMessage(stop, err, a.logger),
		Stopped:         stop,
		ResultsFilename: bulkResultsFilename(time.Now()),
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
// Save errors are as for every save (see saveUserFile).
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
	data, err := bulkResultsCSV(results)
	if err != nil {
		a.logger.Log("bulk results CSV failed: " + core.SanitizeForLog(err.Error()))
		return userErr("Could not create the results file.", err)
	}
	return a.saveUserFile(path, data)
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
	return formatKeyResult(res), nil
}

// Close cancels a running bulk batch and login and wipes the PIN cache.
func (a *App) Close() {
	a.CancelBulk()
	a.CancelLogin()
	a.pinCache.Close()
}
