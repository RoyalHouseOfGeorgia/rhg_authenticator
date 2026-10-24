package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
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
	// onEmit, if set, runs synchronously after each event is recorded, like
	// a host handler that calls back into the App.
	onEmit func(name string)
}

func (e *fakeEvents) Emit(name string, payload any) {
	e.mu.Lock()
	e.names = append(e.names, name)
	e.payloads = append(e.payloads, payload)
	onEmit := e.onEmit
	e.mu.Unlock()
	if onEmit != nil {
		onEmit(name)
	}
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
		DataDir:       dir,
		Logger:        debuglog.New(filepath.Join(dir, debuglog.FileName)),
		RegistryURL:   "http://127.0.0.1:1",
		RevocationURL: "http://127.0.0.1:1",
		Keyring:       kr,
		Prompter:      h.prompter,
		Events:        h.events,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	app.openAdapter = h.openAdapter
	// Online with the in-test signer's key, as if New had fetched it.
	app.reg, app.registryFetched = registryWith(core.KeyEntry{Authority: "Harness", From: "2025-01-01", PublicKey: pubKeyB64(priv)}), true
	h.app = app
	return h
}

// pubKeyB64 is priv's raw public key in base64, as a registry holds it.
func pubKeyB64(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// registryWith returns a registry of entries, each completed with the
// algorithm.
func registryWith(entries ...core.KeyEntry) core.Registry {
	for i := range entries {
		entries[i].Algorithm = core.SupportedAlgorithm
	}
	return core.Registry{Keys: entries}
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

// receive returns the next value from ch, failing the test after 5 s instead
// of hanging until the package timeout.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the operation to finish")
		var zero T
		return zero
	}
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
	want := Info{
		Version: buildinfo.Display(), Online: true, ActiveKeys: 1, RecentlyExpired: 1,
		StatusItems: []string{"Active keys: 1", "Expired (30d): 1", "Version " + strings.TrimPrefix(buildinfo.Display(), "v")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Info = %+v, want %+v", got, want)
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
		} else if want := []string{"No internet", "Version " + strings.TrimPrefix(buildinfo.Display(), "v")}; !reflect.DeepEqual(info.StatusItems, want) {
			t.Errorf("%s: StatusItems = %q, want %q", name, info.StatusItems, want)
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
	if log := h.debugLog(t); !strings.Contains(log, "pin prompt: boom") {
		t.Errorf("debug log = %q, want the prompter error", log)
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
	if !strings.HasPrefix(res.URL, "https://") || res.Existing || len(res.PNGPreview) == 0 {
		t.Errorf("unexpected result: URL=%q Existing=%v png=%d", res.URL, res.Existing, len(res.PNGPreview))
	}
	// The file names carry the first 8 hex digits of the payload hash.
	hash8 := strings.TrimSuffix(strings.TrimPrefix(res.SVGFilename, "rhg-credential-2026-03-14-"), "-min3cm.svg")
	if len(hash8) != 8 || strings.Trim(hash8, "0123456789abcdef") != "" {
		t.Errorf("SVGFilename = %q, want rhg-credential-2026-03-14-<8 hex>-min3cm.svg", res.SVGFilename)
	}
	if want := "rhg-credential-2026-03-14-" + hash8 + "-2048px.png"; res.PNGFilename != want {
		t.Errorf("PNGFilename = %q, want %q", res.PNGFilename, want)
	}
	names, _ := h.events.snapshot()
	if len(names) != 2 || names[0] != "sign.connecting" || names[1] != EventHistoryChanged {
		t.Errorf("events = %v, want [sign.connecting history.changed]", names)
	}
	if hist := h.app.History(""); len(hist.Rows) != 1 || hist.Rows[0].Record.Recipient != res.Recipient {
		t.Errorf("history after Sign = %+v, want the new record", hist.Rows)
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

func TestSign_LogAppendFailureWarns(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.logPath = filepath.Join(t.TempDir(), "missing", "issuances.json")
	res, err := h.app.Sign(context.Background(), validFields("Unlogged"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.Warning != msgNotLogged || res.URL == "" {
		t.Errorf("Warning = %q, URL = %q; want the not-recorded warning and a URL", res.Warning, res.URL)
	}

	h.app.logPath = filepath.Join(h.dir, "issuances.json")
	if res, err := h.app.Sign(context.Background(), validFields("Logged")); err != nil || res.Warning != "" {
		t.Errorf("logged Sign = %+v, %v; want no warning", res, err)
	}
}

func TestSign_ValidationError(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	_, err := h.app.Sign(context.Background(), validFields("   "))
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *SignError", err)
	}
	if se.Message != "Recipient is required." || se.OfferReport || se.Error() != se.Message {
		t.Errorf("SignError = %+v", se)
	}
	if h.prompter.callCount() != 0 || h.opens != 0 {
		t.Error("validation error reached the PIN prompt or card")
	}
}

func TestSign_FlowErrorOffersReport(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		kr   ghapi.Keyring
	}{
		{"with keyring", ghapi.NewFakeKeyring()},
		{"without keyring (browser form)", nil},
	} {
		h := newAppHarness(t, tc.kr)
		h.openErr = boom
		_, err := h.app.Sign(context.Background(), validFields("Alice"))
		var se *SignError
		if !errors.As(err, &se) {
			t.Fatalf("%s: err = %v, want *SignError", tc.name, err)
		}
		if se.Message != "Signing failed. Export the error log for details." || !se.OfferReport {
			t.Errorf("%s: SignError = %+v", tc.name, se)
		}
		if !errors.Is(err, boom) {
			t.Errorf("%s: SignError does not unwrap to the flow error", tc.name)
		}
	}
}

func TestSign_UnlistedHonorRefusedBeforePIN(t *testing.T) {
	h := newAppHarness(t, nil)
	f := validFields("Alice")
	f.Honor = "Order of Something Else"
	const want = "Honor title must be one of the listed titles."
	if err := f.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate err = %v, want %q", err, want)
	}
	_, err := h.app.Sign(context.Background(), f)
	var se *SignError
	if !errors.As(err, &se) || se.Message != want || se.OfferReport {
		t.Fatalf("Sign err = %#v, want a SignError %q", err, want)
	}
	if h.prompter.callCount() != 0 || h.opens != 0 {
		t.Errorf("an unlisted honor reached the PIN prompt (%d) or the card (%d)", h.prompter.callCount(), h.opens)
	}
}

func TestSign_CancelIsContextCanceled(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.prompter.pin = ""
	_, err := h.app.Sign(context.Background(), validFields("Alice"))
	var se *SignError
	if errors.As(err, &se) {
		t.Fatalf("err = %#v, want a plain cancel, not a SignError", err)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, errSigningCancelled) || err.Error() != "Signing cancelled." {
		t.Errorf("err = %v, want context.Canceled with the cancel text", err)
	}
	if names, _ := h.events.snapshot(); len(names) != 0 {
		t.Errorf("events = %v, want none for a cancel", names)
	}
}

// --- SaveQR / ReportSignError ---

func TestSaveQR_WritesFormatsAndLogsFailure(t *testing.T) {
	h := newAppHarness(t, nil)
	res, err := h.app.Sign(context.Background(), validFields("Alice"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	svgPath, pngPath := filepath.Join(out, "q.svg"), filepath.Join(out, "q.png")
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
	if err := h.app.SaveQR(res.URL, "gif", filepath.Join(out, "q.gif")); err == nil || err.Error() != "Unsupported QR format." {
		t.Errorf("unsupported format err = %v", err)
	}
	if err := h.app.SaveQR(res.URL, "png", filepath.Join(out, "missing", "q.png")); !errors.Is(err, fs.ErrNotExist) || err.Error() != msgSaveNoFolder {
		t.Errorf("write into a missing directory err = %v", err)
	}
	if !strings.Contains(h.debugLog(t), "save failed: ") {
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

func TestReportSignError_NonReportableHasNoID(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	if se := signError(t, h, SignFields{}); se.OfferReport || se.ReportID != "" {
		t.Errorf("validation SignError = %+v, want no report id", se)
	}
	for _, id := range []string{"", "1", "bogus"} {
		res, err := h.app.ReportSignError(context.Background(), id)
		if !errors.Is(err, ErrNotFound) || res != (ReportResult{}) || err.Error() != "This failure can no longer be reported." {
			t.Errorf("ReportSignError(%q) = %+v, %v; want ErrNotFound", id, res, err)
		}
	}
}

// stubReportIssue makes ReportSignError's filing return url and filed,
// recording each issue title.
func stubReportIssue(h *appHarness, url string, filed bool) *[]string {
	var titles []string
	h.app.reportIssue = func(_ context.Context, _ *ghapi.Client, title, _ string) (string, bool) {
		titles = append(titles, title)
		return url, filed
	}
	return &titles
}

func TestReportSignError_OnlyLatestFailure(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	titles := stubReportIssue(h, "https://github.com/o/r/issues/7", true)
	h.openErr = errors.New("boom")
	first := signError(t, h, validFields("Alice"))
	h.openErr = errors.New("certificate missing")
	second := signError(t, h, validFields("Bob"))
	if first.ReportID == "" || second.ReportID == "" || first.ReportID == second.ReportID {
		t.Fatalf("report ids = %q, %q; want two distinct ids", first.ReportID, second.ReportID)
	}

	res, err := h.app.ReportSignError(context.Background(), first.ReportID)
	if !errors.Is(err, ErrNotFound) || res != (ReportResult{}) {
		t.Errorf("stale id = %+v, %v; want ErrNotFound", res, err)
	}
	if len(*titles) != 0 {
		t.Fatalf("stale id filed %v", *titles)
	}

	for range 2 { // a repeat returns the filed issue without filing again
		res, err = h.app.ReportSignError(context.Background(), second.ReportID)
		if err != nil || res != (ReportResult{URL: "https://github.com/o/r/issues/7", Filed: true}) {
			t.Errorf("latest id = %+v, %v; want filed", res, err)
		}
	}
	want := errorreport.BuildIssueTitle("signing", second.Message)
	if len(*titles) != 1 || (*titles)[0] != want {
		t.Errorf("filed titles = %q, want one %q", *titles, want)
	}

	// A newer failure is reportable again.
	third := signError(t, h, validFields("Carol"))
	if _, err := h.app.ReportSignError(context.Background(), third.ReportID); err != nil || len(*titles) != 2 {
		t.Errorf("newer failure: err = %v, filed %d issues; want 2", err, len(*titles))
	}
}

func TestReportSignError_BrowserFormCanRepeat(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	titles := stubReportIssue(h, "https://github.com/o/r/issues/new?title=x", false)
	h.openErr = errors.New("boom")
	id := signError(t, h, validFields("Alice")).ReportID
	for range 2 {
		if res, err := h.app.ReportSignError(context.Background(), id); err != nil || res.Filed {
			t.Fatalf("ReportSignError = %+v, %v", res, err)
		}
	}
	if len(*titles) != 2 {
		t.Errorf("tries = %d, want 2", len(*titles))
	}
}

func TestReportSignError_Busy(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	titles := stubReportIssue(h, "https://github.com/o/r/issues/7", true)
	h.openErr = errors.New("boom")
	id := signError(t, h, validFields("Alice")).ReportID
	h.app.reporting.Store(true)
	if _, err := h.app.ReportSignError(context.Background(), id); err != ErrBusy {
		t.Errorf("err = %v, want ErrBusy", err)
	}
	if len(*titles) != 0 {
		t.Errorf("busy report filed %v", *titles)
	}
}

func TestReportSignError_Results(t *testing.T) {
	for _, tc := range []struct {
		name, url string
		filed     bool
		want      ReportResult
	}{
		{"filed", "https://github.com/o/r/issues/7", true, ReportResult{URL: "https://github.com/o/r/issues/7", Filed: true}},
		{"browser form", "https://github.com/o/r/issues/new?title=x", false, ReportResult{URL: "https://github.com/o/r/issues/new?title=x"}},
		{"filed, non-GitHub URL", "https://evil.example/issues/7", true, ReportResult{Filed: true}},
		{"filed, empty URL", "", true, ReportResult{Filed: true}},
		{"non-GitHub URL", "https://evil.example/issues/new", false, ReportResult{}},
		{"empty URL", "", false, ReportResult{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, ghapi.NewFakeKeyring())
			titles := stubReportIssue(h, tc.url, tc.filed)
			h.openErr = errors.New("boom")
			id := signError(t, h, validFields("Alice")).ReportID
			res, err := h.app.ReportSignError(context.Background(), id)
			if res != tc.want || err != nil {
				t.Errorf("ReportSignError = %+v, %v; want %+v", res, err, tc.want)
			}
			// A filed issue is never filed again; anything else may be retried.
			wantCalls := 2
			if tc.filed {
				wantCalls = 1
			}
			res, _ = h.app.ReportSignError(context.Background(), id)
			if res != tc.want || len(*titles) != wantCalls {
				t.Errorf("repeat = %+v after %d reports; want %+v after %d", res, len(*titles), tc.want, wantCalls)
			}
		})
	}
}

func TestReportSignError_ReturnsBrowserURL(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.openErr = errors.New("boom")
	res, err := h.app.ReportSignError(context.Background(), signError(t, h, validFields("Alice")).ReportID)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.Filed || ghapi.ParseGitHubURL(res.URL) == nil || !strings.Contains(res.URL, "/issues/new") {
		t.Errorf("result = %+v, want a GitHub new-issue URL, not filed", res)
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
	// The first Sign's key read and signing open.
	if h.opens != 2 || h.prompter.callCount() != 1 {
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
	r := receive(t, runDone)
	if r.err != nil || r.out.StopMessage != "Cancelled." || r.out.Stopped != BulkCancelled {
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
	if got := h.app.Info(); got.Version != buildinfo.Display() {
		t.Errorf("Info().Version = %q", got.Version)
	}
	h.prompter.release <- struct{}{}
	receive(t, done)
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
	if _, err := h.app.LoadBulk(filepath.Join(h.dir, "missing.csv")); !errors.Is(err, fs.ErrNotExist) || err.Error() != "Could not open the CSV file." {
		t.Errorf("missing file err = %v, want the open message wrapping fs.ErrNotExist", err)
	}
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, "")); err == nil || err.Error() != "File is empty." {
		t.Errorf("empty CSV err = %v", err)
	}
	if log := h.debugLog(t); !strings.Contains(log, "bulk load: open ") || !strings.Contains(log, "bulk load: file is empty") {
		t.Errorf("load failures not logged:\n%s", log)
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

	start := time.Now().UTC().Truncate(time.Second)
	out, err := h.app.RunBulk(context.Background())
	if err != nil {
		t.Fatalf("RunBulk: %v", err)
	}
	if !strings.HasPrefix(out.SummaryLine, "Processed 4 rows: 3 successful") || out.StopMessage != "" || out.Stopped != BulkCompleted {
		t.Errorf("outcome = %+v", out)
	}
	stamp, err := time.Parse("rhg-bulk-results-2006-01-02-150405.csv", out.ResultsFilename)
	if err != nil || stamp.Before(start) || stamp.After(time.Now().UTC()) {
		t.Errorf("ResultsFilename = %q, want one stamped with the run's end time", out.ResultsFilename)
	}
	names, payloads := h.events.snapshot()
	if len(names) != 5 || names[0] != "bulk.connecting" || names[1] != "bulk.progress" || names[4] != EventHistoryChanged {
		t.Fatalf("events = %v, want connecting, 3 progress, history.changed", names)
	}
	if hist := h.app.History(""); len(hist.Rows) != 3 {
		t.Errorf("history after RunBulk has %d rows, want 3", len(hist.Rows))
	}
	if p, ok := payloads[1].(BulkProgress); !ok || p != (BulkProgress{Done: 0, Total: 3, Name: "Alice"}) {
		t.Errorf("first progress = %#v", payloads[1])
	}

	csvPath := filepath.Join(t.TempDir(), "results.csv")
	if err := h.app.ExportBulkResults(csvPath); err != nil {
		t.Fatalf("ExportBulkResults: %v", err)
	}
	if data, _ := os.ReadFile(csvPath); !strings.Contains(string(data), "Alice") {
		t.Errorf("results CSV:\n%s", data)
	}
	if err := h.app.ExportBulkResults(filepath.Join(t.TempDir(), "missing", "r.csv")); !errors.Is(err, fs.ErrNotExist) || err.Error() != msgSaveNoFolder {
		t.Errorf("export into a missing directory err = %v", err)
	}
	if !strings.Contains(h.debugLog(t), "save failed: ") {
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
	if err != nil || !strings.HasPrefix(out.StopMessage, "Batch stopped: Incorrect PIN") || out.Stopped != BulkFailed {
		t.Errorf("RunBulk = %+v, %v", out, err)
	}
	// The row that stopped the batch is listed too (bulk.run's failed example).
	if len(out.FailedLines) != 1 || !strings.HasPrefix(out.FailedLines[0], "line 2: Incorrect PIN") {
		t.Errorf("FailedLines = %q", out.FailedLines)
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
		result  KeyCheckResult
		want    string
	}{
		{"registered key", registered, nil, KeyCheckFound, "Key found in registry"},
		{"unknown key", core.Registry{}, nil, KeyCheckNotFound, "Key NOT found in registry"},
		{"no key plugged in", registered, errors.New("no YubiKey found among 0 smart card(s)"), KeyCheckFailed, "Please plug in your YubiKey and try again"},
	} {
		h.app.reg, h.openErr = tc.reg, tc.openErr
		kc, err := h.app.CheckYubiKey()
		if err != nil || kc.Outcome != tc.result || kc.Status != tc.want {
			t.Errorf("%s: CheckYubiKey = %+v, %v; want %q with status %q", tc.name, kc, err, tc.result, tc.want)
		}
	}
	if !strings.Contains(h.debugLog(t), "yubikey check: yubikey: no YubiKey found") {
		t.Error("key check failure not logged")
	}

	// Offline the registry is empty, so a registered key must not be shown
	// as missing: the check reports the registry and reads no card.
	h.app.reg, h.app.registryFetched, h.openErr = core.Registry{}, false, nil
	opens := h.opens
	kc, err := h.app.CheckYubiKey()
	if err != nil || kc.Outcome != KeyCheckFailed || kc.Status != msgRegistryUnavailable || h.opens != opens {
		t.Errorf("offline CheckYubiKey = %+v, %v (opens %d→%d)", kc, err, opens, h.opens)
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
	if out := receive(t, runDone); out.StopMessage != "Cancelled." || out.Stopped != BulkCancelled {
		t.Errorf("outcome = %+v, want Cancelled.", out)
	}
	if _, ok := h.app.pinCache.Get(); ok {
		t.Error("PIN cache not wiped by Close")
	}
}

func TestLoadBulk_FailedOpenClearsPlan(t *testing.T) {
	h := newAppHarness(t, nil)
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, "name,honor,detail,date\nBob,Other,Help,2026-03-14\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.LoadBulk(filepath.Join(h.dir, "missing.csv")); err == nil {
		t.Fatal("LoadBulk of a missing file succeeded")
	}
	if _, err := h.app.RunBulk(context.Background()); !errors.Is(err, ErrNoBulkPlan) {
		t.Errorf("RunBulk after a failed load: err = %v, want ErrNoBulkPlan (never the earlier file)", err)
	}
	if h.prompter.callCount() != 0 {
		t.Error("RunBulk prompted for a PIN")
	}
}

func TestLoadHistory_HandlerMayCallBack(t *testing.T) {
	h := newAppHarness(t, nil)
	var reloaded atomic.Bool
	h.events.mu.Lock()
	h.events.onEmit = func(name string) {
		if name == EventHistoryChanged && reloaded.CompareAndSwap(false, true) {
			h.app.loadHistory() // re-entered from the handler
		}
	}
	h.events.mu.Unlock()
	done := make(chan struct{})
	go func() {
		h.app.loadHistory()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loadHistory deadlocked when its event handler reloaded the history")
	}
}

func TestSign_QRFailureAfterRecordReloadsHistory(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	prev := generatePreviewPNG
	t.Cleanup(func() { generatePreviewPNG = prev })
	generatePreviewPNG = func(string, int) ([]byte, error) { return nil, errors.New("encode failed") }

	_, err := h.app.Sign(context.Background(), validFields("Alice"))
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a SignError", err)
	}
	if names, _ := h.events.snapshot(); !slices.Contains(names, EventHistoryChanged) {
		t.Errorf("events = %v, want history.changed for the record written before the QR failed", names)
	}
	if hist := h.app.History(""); len(hist.Rows) != 1 {
		t.Errorf("history has %d rows, want the written record", len(hist.Rows))
	}
}

func TestReportSignError_UsesSessionAndTimeout(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	var gotClient *ghapi.Client
	var deadline time.Time
	var hasDeadline bool
	h.app.reportIssue = func(ctx context.Context, client *ghapi.Client, _, _ string) (string, bool) {
		gotClient = client
		deadline, hasDeadline = ctx.Deadline()
		return "", false // the browser form: the failure stays reportable
	}
	h.openErr = errors.New("boom")
	id := signError(t, h, validFields("Alice")).ReportID

	start := time.Now()
	if _, err := h.app.ReportSignError(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	end := time.Now()
	if gotClient != nil {
		t.Error("logged out: reportIssue got a client, want nil (the browser form)")
	}
	if !hasDeadline || deadline.Before(start.Add(reportTimeout)) || deadline.After(end.Add(reportTimeout)) {
		t.Errorf("deadline = %v after the call (set %v), want %v", deadline.Sub(start), hasDeadline, reportTimeout)
	}

	session := ghapi.NewClient("tok")
	logIn(h, session)
	if _, err := h.app.ReportSignError(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if gotClient != session {
		t.Error("logged in: reportIssue did not get the App's session client")
	}
}
