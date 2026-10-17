package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// fakePrompter returns pin/remember/err. With block set it waits for ctx.Done
// or release first. Each call is signalled on entered.
type fakePrompter struct {
	mu         sync.Mutex
	pin        string
	remember   bool
	err        error
	block      bool
	calls      int
	gotDefault bool
	entered    chan struct{}
	release    chan struct{}
}

func newFakePrompter(pin string, remember bool) *fakePrompter {
	return &fakePrompter{pin: pin, remember: remember, entered: make(chan struct{}, 10), release: make(chan struct{})}
}

func (p *fakePrompter) RequestPIN(ctx context.Context, rememberDefault bool) (string, bool, error) {
	p.mu.Lock()
	p.calls++
	p.gotDefault = rememberDefault
	block := p.block
	p.mu.Unlock()
	p.entered <- struct{}{}
	if block {
		select {
		case <-ctx.Done():
		case <-p.release:
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pin, p.remember, p.err
}

func (p *fakePrompter) setBlock(b bool) {
	p.mu.Lock()
	p.block = b
	p.mu.Unlock()
}

func (p *fakePrompter) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// fakeEvents records emitted event names and payloads.
type fakeEvents struct {
	mu       sync.Mutex
	names    []string
	payloads []any
}

func (e *fakeEvents) Emit(name string, payload any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.names = append(e.names, name)
	e.payloads = append(e.payloads, payload)
}

func (e *fakeEvents) snapshot() ([]string, []any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.names...), append([]any(nil), e.payloads...)
}

// waitFor waits until name has been emitted.
func (e *fakeEvents) waitFor(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		names, _ := e.snapshot()
		for _, n := range names {
			if n == name {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not emitted; got %v", name, names)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *fakeEvents) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.names, e.payloads = nil, nil
}

func testKeyB64(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// registryServer serves a registry with one active key and one that expired
// five days ago.
func registryServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	expired := time.Now().UTC().AddDate(0, 0, -5).Format("2006-01-02")
	body := `{"keys": [
		{"authority": "A", "from": "2025-01-01", "to": null, "algorithm": "Ed25519", "public_key": "` + testKeyB64(1) + `", "note": ""},
		{"authority": "B", "from": "2025-01-01", "to": "` + expired + `", "algorithm": "Ed25519", "public_key": "` + testKeyB64(100) + `", "note": ""}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// appHarness is an App wired to fakes, a temp DataDir and an in-test signer.
type appHarness struct {
	app      *App
	prompter *fakePrompter
	events   *fakeEvents
	dir      string
	opens    int
	openErr  error
	signer   func(ed25519.PrivateKey) core.SigningAdapter
	priv     ed25519.PrivateKey
	openMu   sync.Mutex
}

func newAppHarness(t *testing.T, kr ghapi.Keyring) *appHarness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	h := &appHarness{
		prompter: newFakePrompter("123456", false),
		events:   &fakeEvents{},
		dir:      dir,
		priv:     priv,
		signer:   func(k ed25519.PrivateKey) core.SigningAdapter { return &mockSignAdapter{secretKey: k} },
	}
	app, err := New(Config{
		DataDir:     dir,
		Logger:      debuglog.New(filepath.Join(dir, debuglog.FileName)),
		RegistryURL: "http://127.0.0.1:1",
		Keyring:     kr,
		Prompter:    h.prompter,
		Events:      h.events,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	app.openAdapter = h.openAdapter
	h.app = app
	return h
}

func (h *appHarness) openAdapter(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
	h.openMu.Lock()
	defer h.openMu.Unlock()
	h.opens++
	if h.openErr != nil {
		return nil, nil, h.openErr
	}
	return h.signer(h.priv), nopCloser{}, nil
}

func (h *appHarness) debugLog(t *testing.T) string {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(h.dir, debuglog.FileName))
	return string(data)
}

func validFields(recipient string) SignFields {
	return SignFields{Recipient: recipient, Honor: "Other", Detail: "Service", Date: "2026-03-14"}
}

// waitEntered waits for the fake prompter to be called.
func waitEntered(t *testing.T, p *fakePrompter) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("RequestPIN was not called")
	}
}

func TestNew_RequiresDataDirPrompterEvents(t *testing.T) {
	p, e := newFakePrompter("", false), &fakeEvents{}
	for name, cfg := range map[string]Config{
		"no DataDir":  {Prompter: p, Events: e},
		"no Prompter": {DataDir: t.TempDir(), Events: e},
		"no Events":   {DataDir: t.TempDir(), Prompter: p},
	} {
		if app, err := New(cfg); err == nil || app != nil {
			t.Errorf("%s: New = %v, %v; want error", name, app, err)
		}
	}
}

func TestNew_OnlineRegistryStats(t *testing.T) {
	srv := registryServer(t, http.StatusOK)
	dir := t.TempDir()
	app, err := New(Config{DataDir: dir, RegistryURL: srv.URL, Prompter: newFakePrompter("", false), Events: &fakeEvents{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer app.Close()
	got := app.Info()
	want := Info{Version: buildinfo.Version, Online: true, ActiveKeys: 1, RecentlyExpired: 1}
	if got != want {
		t.Errorf("Info = %+v, want %+v", got, want)
	}
	if app.LogPath() != filepath.Join(dir, "issuances.json") {
		t.Errorf("LogPath = %q", app.LogPath())
	}
}

func TestNew_RegistryOffline(t *testing.T) {
	for name, url := range map[string]string{
		"500":         registryServer(t, http.StatusInternalServerError).URL,
		"unreachable": "http://127.0.0.1:1",
	} {
		dir := t.TempDir()
		logger := debuglog.New(filepath.Join(dir, debuglog.FileName))
		app, err := New(Config{DataDir: dir, Logger: logger, RegistryURL: url, Prompter: newFakePrompter("", false), Events: &fakeEvents{}})
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		if info := app.Info(); info.Online || info.ActiveKeys != 0 {
			t.Errorf("%s: Info = %+v, want offline with no keys", name, info)
		}
		data, _ := os.ReadFile(logger.Path())
		if !strings.Contains(string(data), "warning: registry fetch failed") || !strings.Contains(string(data), "registry fetch: online=false") {
			t.Errorf("%s: missing fetch log lines:\n%s", name, data)
		}
		app.Close()
	}
}

func TestNew_CleansStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "issuances.json.tmp.abc123")
	keep := filepath.Join(dir, "issuances.json")
	for _, p := range []string{stale, keep} {
		if err := os.WriteFile(p, []byte("[]"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	app, err := New(Config{DataDir: dir, RegistryURL: "http://127.0.0.1:1", Prompter: newFakePrompter("", false), Events: &fakeEvents{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer app.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale tmp file not removed: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("issuance log removed: %v", err)
	}
}

func TestApp_HonorsIsACopy(t *testing.T) {
	h := newAppHarness(t, nil)
	got := h.app.Honors()
	if len(got) != len(honorTitles) {
		t.Fatalf("Honors len = %d, want %d", len(got), len(honorTitles))
	}
	got[0] = "changed"
	if honorTitles[0] == "changed" {
		t.Error("Honors returned the shared slice")
	}
}

// --- PIN rules ---

func TestReadPIN_CacheHitSkipsPrompt(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.pinCache.SetEnabled(true)
	if err := h.app.pinCache.Set("111111"); err != nil {
		t.Fatal(err)
	}
	pin, err := h.app.readPIN(context.Background())
	if err != nil || pin != "111111" {
		t.Fatalf("readPIN = %q, %v; want cached PIN", pin, err)
	}
	if n := h.prompter.callCount(); n != 0 {
		t.Errorf("prompter called %d times on a cache hit", n)
	}
}

func TestReadPIN_RememberFalseNotCached(t *testing.T) {
	h := newAppHarness(t, nil)
	pin, err := h.app.readPIN(context.Background())
	if err != nil || pin != "123456" {
		t.Fatalf("readPIN = %q, %v", pin, err)
	}
	if _, ok := h.app.pinCache.Get(); ok || h.app.pinCache.Enabled() {
		t.Error("PIN cached with remember=false")
	}
}

func TestReadPIN_RememberTrueAppliedBeforeCaching(t *testing.T) {
	h := newAppHarness(t, nil)
	h.prompter.remember = true
	h.prompter.pin = "123456789" // capped to the PIV limit before caching
	pin, err := h.app.readPIN(context.Background())
	if err != nil || pin != "12345678" {
		t.Fatalf("readPIN = %q, %v", pin, err)
	}
	if got, ok := h.app.pinCache.Get(); !ok || got != "12345678" {
		t.Errorf("cache = %q, %v; want the capped PIN", got, ok)
	}
	if h.prompter.gotDefault {
		t.Error("first prompt should default remember to false")
	}

	h.app.pinCache.Clear()
	if _, err := h.app.readPIN(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.prompter.gotDefault {
		t.Error("prompt should default remember to the enabled preference")
	}
}

func TestReadPIN_CancelLeavesRememberUnchanged(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		h := newAppHarness(t, nil)
		h.app.pinCache.SetEnabled(enabled)
		h.prompter.pin = "" // Cancel and OK-with-empty both arrive as ""
		h.prompter.remember = !enabled
		if _, err := h.app.readPIN(context.Background()); !errors.Is(err, errSigningCancelled) {
			t.Errorf("enabled=%v: err = %v, want errSigningCancelled", enabled, err)
		}
		if h.app.pinCache.Enabled() != enabled {
			t.Errorf("enabled=%v: remember preference changed by a cancel", enabled)
		}
	}
}

func TestReadPIN_PrompterError(t *testing.T) {
	h := newAppHarness(t, nil)
	boom := errors.New("boom")
	h.prompter.err = boom
	if _, err := h.app.readPIN(context.Background()); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

func TestReadPIN_Timeout(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.pinTimeout = 20 * time.Millisecond
	h.prompter.setBlock(true)
	if _, err := h.app.readPIN(context.Background()); !errors.Is(err, errPINEntryTimedOut) {
		t.Errorf("err = %v, want errPINEntryTimedOut", err)
	}
}

func TestReadPIN_CallerCancelIsNotTimeout(t *testing.T) {
	h := newAppHarness(t, nil)
	h.prompter.setBlock(true)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-h.prompter.entered
		cancel()
	}()
	if _, err := h.app.readPIN(ctx); !errors.Is(err, errSigningCancelled) {
		t.Errorf("err = %v, want errSigningCancelled", err)
	}
}

func TestSign_PIVAuthErrorClearsCache(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.signer = func(k ed25519.PrivateKey) core.SigningAdapter { return &authErrSignAdapter{secretKey: k} }
	h.prompter.remember = true

	_, err := h.app.Sign(context.Background(), validFields("Alice"))
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *SignError", err)
	}
	if !strings.HasPrefix(se.Message, "Incorrect PIN") {
		t.Errorf("Message = %q", se.Message)
	}
	if _, ok := h.app.pinCache.Get(); ok {
		t.Error("PIN cache not cleared after a PIV auth error")
	}
	if !h.app.pinCache.Enabled() {
		t.Error("auth error must not flip the remember preference")
	}
}

// --- Sign ---

func TestSign_SuccessReturnsCanonicalFields(t *testing.T) {
	h := newAppHarness(t, nil)
	f := SignFields{Recipient: "  Jose\u0301 ", Honor: " Other ", Detail: "\tService\n", Date: " 2026-03-14 "}
	res, err := h.app.Sign(context.Background(), f)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Recipient != "Jos\u00e9" || res.Honor != "Other" || res.Detail != "Service" || res.Date != "2026-03-14" {
		t.Errorf("canonical fields = %q %q %q %q", res.Recipient, res.Honor, res.Detail, res.Date)
	}
	if !strings.HasPrefix(res.URL, "https://") || len(res.Hash8) != 8 || res.Existing || len(res.PNGPreview) == 0 {
		t.Errorf("unexpected result: URL=%q Hash8=%q Existing=%v png=%d", res.URL, res.Hash8, res.Existing, len(res.PNGPreview))
	}
	names, _ := h.events.snapshot()
	if len(names) != 1 || names[0] != "sign.connecting" {
		t.Errorf("events = %v, want [sign.connecting]", names)
	}

	// Re-signing the same credential returns the logged one without a prompt.
	again, err := h.app.Sign(context.Background(), f)
	if err != nil || !again.Existing || again.URL != res.URL {
		t.Errorf("re-sign = %+v, %v; want Existing with the same URL", again, err)
	}
	if n := h.prompter.callCount(); n != 1 {
		t.Errorf("prompter called %d times, want 1", n)
	}
}

func TestSign_ValidationError(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	_, err := h.app.Sign(context.Background(), validFields("   "))
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *SignError", err)
	}
	if se.Message != "recipient is required" || se.OfferReport || se.Error() != se.Message {
		t.Errorf("SignError = %+v", se)
	}
	if h.prompter.callCount() != 0 || h.opens != 0 {
		t.Error("validation error reached the PIN prompt or card")
	}
}

func TestSign_FlowErrorOffersReport(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name  string
		kr    ghapi.Keyring
		offer bool
	}{
		{"with keyring", ghapi.NewFakeKeyring(), true},
		{"without keyring", nil, false},
	} {
		h := newAppHarness(t, tc.kr)
		h.openErr = boom
		_, err := h.app.Sign(context.Background(), validFields("Alice"))
		var se *SignError
		if !errors.As(err, &se) {
			t.Fatalf("%s: err = %v, want *SignError", tc.name, err)
		}
		if se.Message != "Signing failed. Use Help → Export Error Log… for details." || se.OfferReport != tc.offer {
			t.Errorf("%s: SignError = %+v", tc.name, se)
		}
		if !errors.Is(err, boom) {
			t.Errorf("%s: SignError does not unwrap to the flow error", tc.name)
		}
	}
}

func TestSign_CancelHasEmptyMessage(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.prompter.pin = ""
	_, err := h.app.Sign(context.Background(), validFields("Alice"))
	var se *SignError
	if !errors.As(err, &se) || se.Message != "" || se.OfferReport {
		t.Fatalf("err = %#v, want cancel SignError", err)
	}
	if !errors.Is(err, errSigningCancelled) || err.Error() != errSigningCancelled.Error() {
		t.Errorf("Error() = %q", err.Error())
	}
}

// --- SaveQR / ReportSignError ---

func TestSaveQR_WritesFormatsAndLogsFailure(t *testing.T) {
	h := newAppHarness(t, nil)
	res, err := h.app.Sign(context.Background(), validFields("Alice"))
	if err != nil {
		t.Fatal(err)
	}
	svgPath, pngPath := filepath.Join(h.dir, "q.svg"), filepath.Join(h.dir, "q.png")
	if err := h.app.SaveQR(res.URL, "svg", svgPath); err != nil {
		t.Fatalf("svg: %v", err)
	}
	if err := h.app.SaveQR(res.URL, "png", pngPath); err != nil {
		t.Fatalf("png: %v", err)
	}
	if svg, _ := os.ReadFile(svgPath); !strings.Contains(string(svg), "<svg") {
		t.Error("SVG not written")
	}
	if png, _ := os.ReadFile(pngPath); !strings.HasPrefix(string(png), "\x89PNG") {
		t.Error("PNG not written")
	}
	if err := h.app.SaveQR(res.URL, "gif", filepath.Join(h.dir, "q.gif")); err == nil {
		t.Error("unsupported format accepted")
	}
	if err := h.app.SaveQR(res.URL, "png", filepath.Join(h.dir, "missing", "q.png")); err == nil {
		t.Error("write into a missing directory succeeded")
	}
	if !strings.Contains(h.debugLog(t), "PNG save failed") {
		t.Error("save failure not logged")
	}
}

// signError runs a Sign that fails and returns its *SignError.
func signError(t *testing.T, h *appHarness, f SignFields) *SignError {
	t.Helper()
	_, err := h.app.Sign(context.Background(), f)
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("Sign err = %v, want *SignError", err)
	}
	return se
}

func TestReportSignError_RefusesNonReportable(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	invalid := signError(t, h, SignFields{})
	for name, se := range map[string]*SignError{"nil": nil, "validation error": invalid} {
		if url, err := h.app.ReportSignError(context.Background(), se); !errors.Is(err, errNotReportable) || url != "" {
			t.Errorf("%s: ReportSignError = %q, %v; want errNotReportable", name, url, err)
		}
	}
}

func TestReportSignError_NoKeyring(t *testing.T) {
	h := newAppHarness(t, nil)
	se := &SignError{Message: "Signing failed.", OfferReport: true, Err: errors.New("boom")}
	if url, err := h.app.ReportSignError(context.Background(), se); !errors.Is(err, errNotReportable) || url != "" {
		t.Errorf("ReportSignError = %q, %v; want errNotReportable", url, err)
	}
}

func TestReportSignError_ReturnsBrowserURL(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.openErr = errors.New("boom")
	url, err := h.app.ReportSignError(context.Background(), signError(t, h, validFields("Alice")))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ghapi.ParseGitHubURL(url) == nil || !strings.Contains(url, "/issues/new") {
		t.Errorf("url = %q, want a GitHub new-issue URL", url)
	}
}

// --- Busy ---

func TestApp_BusyMethodsReturnErrBusyWithoutTouchingState(t *testing.T) {
	h := newAppHarness(t, nil)
	if _, err := h.app.Sign(context.Background(), validFields("Alice")); err != nil {
		t.Fatal(err)
	}
	h.app.busy.Store(true)
	if _, err := h.app.Sign(context.Background(), validFields("Bob")); err != ErrBusy {
		t.Errorf("Sign err = %v", err)
	}
	if _, err := h.app.LoadBulk("x"); err != ErrBusy {
		t.Errorf("LoadBulk err = %v", err)
	}
	if _, err := h.app.RunBulk(context.Background()); err != ErrBusy {
		t.Errorf("RunBulk err = %v", err)
	}
	if err := h.app.ExportBulkResults("x"); err != ErrBusy {
		t.Errorf("ExportBulkResults err = %v", err)
	}
	if _, err := h.app.CheckYubiKey(); err != ErrBusy {
		t.Errorf("CheckYubiKey err = %v", err)
	}
	if h.opens != 1 || h.prompter.callCount() != 1 {
		t.Errorf("a refused call reached the card or the PIN prompt (opens=%d, prompts=%d)", h.opens, h.prompter.callCount())
	}
}

func writeCSV(t *testing.T, dir, text string) string {
	t.Helper()
	p := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApp_BusyAcrossSignAndBulk(t *testing.T) {
	h := newAppHarness(t, nil)

	// A Sign blocked in RequestPIN holds the busy flag.
	h.prompter.setBlock(true)
	done := make(chan error, 1)
	go func() {
		_, err := h.app.Sign(context.Background(), validFields("Alice"))
		done <- err
	}()
	waitEntered(t, h.prompter)
	if _, err := h.app.CheckYubiKey(); err != ErrBusy {
		t.Errorf("CheckYubiKey during Sign: err = %v, want ErrBusy", err)
	}
	h.prompter.release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// A bulk run blocked in RequestPIN: Sign is refused.
	plan, err := h.app.LoadBulk(writeCSV(t, h.dir, "name,honor,detail,date\nBob,Other,Help,2026-03-14\n"))
	if err != nil || plan.ToSign != 1 {
		t.Fatalf("LoadBulk = %+v, %v", plan, err)
	}
	type runResult struct {
		out BulkOutcome
		err error
	}
	runDone := make(chan runResult, 1)
	go func() {
		out, err := h.app.RunBulk(context.Background())
		runDone <- runResult{out, err}
	}()
	waitEntered(t, h.prompter)
	if _, err := h.app.Sign(context.Background(), validFields("Carol")); err != ErrBusy {
		t.Errorf("Sign during bulk: err = %v, want ErrBusy", err)
	}
	h.app.CancelBulk()
	r := <-runDone
	if r.err != nil || r.out.StopMessage != "Cancelled." {
		t.Errorf("RunBulk = %+v, %v; want Cancelled.", r.out, r.err)
	}
}

func TestApp_InfoWhileSignBlocked(t *testing.T) {
	h := newAppHarness(t, nil)
	h.prompter.setBlock(true)
	done := make(chan struct{})
	go func() {
		_, _ = h.app.Sign(context.Background(), validFields("Alice"))
		close(done)
	}()
	waitEntered(t, h.prompter)
	// Regression guard: Info must not wait on anything held across the PIN
	// prompt; a deadlock fails this test by timeout.
	if got := h.app.Info(); got.Version != buildinfo.Version {
		t.Errorf("Info().Version = %q", got.Version)
	}
	h.prompter.release <- struct{}{}
	<-done
}

// --- Bulk ---

func TestBulk_NoPlan(t *testing.T) {
	h := newAppHarness(t, nil)
	if _, err := h.app.RunBulk(context.Background()); !errors.Is(err, ErrNoBulkPlan) {
		t.Errorf("RunBulk err = %v", err)
	}
	if err := h.app.ExportBulkResults(filepath.Join(h.dir, "r.csv")); !errors.Is(err, ErrNoBulkPlan) {
		t.Errorf("ExportBulkResults err = %v", err)
	}
	h.app.CancelBulk() // nothing running: no-op
}

func TestBulk_LoadErrors(t *testing.T) {
	h := newAppHarness(t, nil)
	if _, err := h.app.LoadBulk(filepath.Join(h.dir, "missing.csv")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, "")); err == nil {
		t.Error("empty CSV accepted")
	}
	if _, err := h.app.RunBulk(context.Background()); !errors.Is(err, ErrNoBulkPlan) {
		t.Errorf("failed load left a plan: %v", err)
	}
}

func TestBulk_LoadRunExport(t *testing.T) {
	h := newAppHarness(t, nil)
	plan, err := h.app.LoadBulk(writeCSV(t, h.dir, threeRowCSV+"Bad,Nope,X,2026-03-14\n"))
	if err != nil {
		t.Fatalf("LoadBulk: %v", err)
	}
	if plan.ToSign != 3 || plan.CountsLine != "4 rows: 3 to sign, 0 already issued, 1 invalid" ||
		strings.Join(plan.PreviewNames, ",") != "Alice,Bob,Dave" || len(plan.InvalidLines) != 1 {
		t.Errorf("plan = %+v", plan)
	}

	out, err := h.app.RunBulk(context.Background())
	if err != nil {
		t.Fatalf("RunBulk: %v", err)
	}
	if !strings.HasPrefix(out.SummaryLine, "Processed 4 rows: 3 successful") || out.StopMessage != "" {
		t.Errorf("outcome = %+v", out)
	}
	names, payloads := h.events.snapshot()
	if len(names) != 4 || names[0] != "bulk.connecting" || names[1] != "bulk.progress" {
		t.Fatalf("events = %v", names)
	}
	if p, ok := payloads[1].(BulkProgress); !ok || p != (BulkProgress{Done: 0, Total: 3, Name: "Alice"}) {
		t.Errorf("first progress = %#v", payloads[1])
	}

	csvPath := filepath.Join(h.dir, "results.csv")
	if err := h.app.ExportBulkResults(csvPath); err != nil {
		t.Fatalf("ExportBulkResults: %v", err)
	}
	if data, _ := os.ReadFile(csvPath); !strings.Contains(string(data), "Alice") {
		t.Errorf("results CSV:\n%s", data)
	}
	if err := h.app.ExportBulkResults(filepath.Join(h.dir, "missing", "r.csv")); err == nil {
		t.Error("export into a missing directory succeeded")
	}
	if !strings.Contains(h.debugLog(t), "bulk results save failed") {
		t.Error("export failure not logged")
	}
}

func TestBulk_AuthErrorClearsCacheAndStops(t *testing.T) {
	h := newAppHarness(t, nil)
	h.signer = func(k ed25519.PrivateKey) core.SigningAdapter { return &authErrSignAdapter{secretKey: k} }
	h.prompter.remember = true
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, threeRowCSV)); err != nil {
		t.Fatal(err)
	}
	out, err := h.app.RunBulk(context.Background())
	if err != nil || !strings.HasPrefix(out.StopMessage, "Batch stopped: Incorrect PIN") {
		t.Errorf("RunBulk = %+v, %v", out, err)
	}
	if _, ok := h.app.pinCache.Get(); ok {
		t.Error("PIN cache not cleared after a PIV auth error")
	}
}

// --- CheckYubiKey / Close ---

func TestApp_CheckYubiKey(t *testing.T) {
	h := newAppHarness(t, nil)
	pub := base64.StdEncoding.EncodeToString(h.priv.Public().(ed25519.PublicKey))
	registered := core.Registry{Keys: []core.KeyEntry{{Authority: "A", From: "2025-01-01", Algorithm: core.SupportedAlgorithm, PublicKey: pub}}}
	for _, tc := range []struct {
		name    string
		reg     core.Registry
		openErr error
		want    string
	}{
		{"registered key", registered, nil, "Key found in registry"},
		{"unknown key", core.Registry{}, nil, "Key NOT found in registry"},
		{"no key plugged in", registered, errors.New("no YubiKey found among 0 smart card(s)"), "Please plug in your YubiKey and try again"},
	} {
		h.app.reg, h.openErr = tc.reg, tc.openErr
		kc, err := h.app.CheckYubiKey()
		if err != nil || kc.Status != tc.want {
			t.Errorf("%s: CheckYubiKey = %+v, %v; want status %q", tc.name, kc, err, tc.want)
		}
	}
	if !strings.Contains(h.debugLog(t), "yubikey check: yubikey: no YubiKey found") {
		t.Error("key check failure not logged")
	}
}

func TestApp_CloseWipesPINCacheAndCancelsBulk(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.pinCache.SetEnabled(true)
	if err := h.app.pinCache.Set("123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, threeRowCSV)); err != nil {
		t.Fatal(err)
	}
	h.app.pinCache.Clear() // force a prompt so the run blocks
	h.prompter.setBlock(true)
	runDone := make(chan BulkOutcome, 1)
	go func() {
		out, _ := h.app.RunBulk(context.Background())
		runDone <- out
	}()
	waitEntered(t, h.prompter)
	if err := h.app.pinCache.Set("123456"); err != nil {
		t.Fatal(err)
	}

	h.app.Close()
	if out := <-runDone; out.StopMessage != "Cancelled." {
		t.Errorf("StopMessage = %q, want Cancelled.", out.StopMessage)
	}
	if _, ok := h.app.pinCache.Get(); ok {
		t.Error("PIN cache not wiped by Close")
	}
}
