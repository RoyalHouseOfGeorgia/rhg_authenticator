package gui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// findButton walks obj (containers and widget renderers) and returns the
// first button labelled text, or nil.
func findButton(t *testing.T, obj fyne.CanvasObject, text string) *widget.Button {
	t.Helper()
	switch o := obj.(type) {
	case *widget.Button:
		if o.Text == text {
			return o
		}
		return nil
	case *fyne.Container:
		for _, child := range o.Objects {
			if b := findButton(t, child, text); b != nil {
				return b
			}
		}
		return nil
	case fyne.Widget:
		for _, child := range test.TempWidgetRenderer(t, o).Objects() {
			if b := findButton(t, child, text); b != nil {
				return b
			}
		}
	}
	return nil
}

// labelTexts collects the text of every label under obj.
func labelTexts(t *testing.T, obj fyne.CanvasObject) []string {
	var out []string
	switch o := obj.(type) {
	case *widget.Label:
		return []string{o.Text}
	case *fyne.Container:
		for _, child := range o.Objects {
			out = append(out, labelTexts(t, child)...)
		}
	case fyne.Widget:
		for _, child := range test.TempWidgetRenderer(t, o).Objects() {
			out = append(out, labelTexts(t, child)...)
		}
	}
	return out
}

func topOverlay(t *testing.T, w fyne.Window) fyne.CanvasObject {
	t.Helper()
	top := w.Canvas().Overlays().Top()
	if top == nil {
		t.Fatal("expected a dialog overlay, got none")
	}
	return top
}

func tapOverlayButton(t *testing.T, w fyne.Window, text string) {
	t.Helper()
	b := findButton(t, topOverlay(t, w), text)
	if b == nil {
		t.Fatalf("no %q button in top overlay", text)
	}
	test.Tap(b)
}

// bulkUIHarness wires bulkSignDeps to a test window, a synchronous launcher,
// the bulkHarness fakes, and a cached PIN (so no PIN dialog is shown).
type bulkUIHarness struct {
	*bulkHarness
	w        fyne.Window
	busy     []bool
	launches int
	deps     bulkSignDeps
}

func newBulkUIHarness(t *testing.T) *bulkUIHarness {
	t.Helper()
	test.NewTempApp(t)
	w := test.NewWindow(nil)
	w.Resize(fyne.NewSize(800, 600))
	t.Cleanup(w.Close)

	cache := yubikey.NewPinCache()
	t.Cleanup(cache.Close)
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("seeding PIN cache: %v", err)
	}

	h := &bulkUIHarness{bulkHarness: newBulkHarness(t), w: w}
	h.deps = bulkSignDeps{
		window:      w,
		logPath:     h.logPath,
		launchGo:    func(fn func()) { h.launches++; fn() },
		openAdapter: h.openAdapter,
		pinCache:    cache,
		logger:      h.logger,
		setBusy:     func(b bool) { h.busy = append(h.busy, b) },
	}
	return h
}

func (h *bulkUIHarness) lastBusy(t *testing.T) bool {
	t.Helper()
	if len(h.busy) == 0 {
		t.Fatal("setBusy never called")
	}
	return h.busy[len(h.busy)-1]
}

// mockSignAdapter mirrors core/sign_test.go's mockAdapter.
// Intentionally duplicated to keep test packages independent.
type mockSignAdapter struct {
	secretKey ed25519.PrivateKey
}

func (m *mockSignAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], m.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (m *mockSignAdapter) SignBytes(data []byte) ([]byte, error) {
	return ed25519.Sign(m.secretKey, data), nil
}

// authErrSignAdapter has a valid ExportPublicKey but fails SignBytes with a
// PIV PIN authentication error, as a wrong PIN would.
type authErrSignAdapter struct {
	secretKey ed25519.PrivateKey
}

func (a *authErrSignAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], a.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (a *authErrSignAdapter) SignBytes(data []byte) ([]byte, error) {
	return nil, piv.AuthErr{Retries: 2}
}

// nopCloser wraps io.NopCloser for adapter closers.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// bulkHarness bundles a temp audit log, debug logger, and a call-counting
// openAdapter fake backed by an in-test ed25519 key.
type bulkHarness struct {
	logPath   string
	logger    *debuglog.Logger
	priv      ed25519.PrivateKey
	opens     int
	newSigner func(ed25519.PrivateKey) core.SigningAdapter
}

func newBulkHarness(t *testing.T) *bulkHarness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	return &bulkHarness{
		logPath: filepath.Join(dir, "issuances.json"),
		logger:  debuglog.New(filepath.Join(dir, "debug.log")),
		priv:    priv,
		newSigner: func(k ed25519.PrivateKey) core.SigningAdapter {
			return &mockSignAdapter{secretKey: k}
		},
	}
}

func (h *bulkHarness) openAdapter(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
	h.opens++
	return h.newSigner(h.priv), nopCloser{}, nil
}

func (h *bulkHarness) plan(t *testing.T, csvText string) []bulk.Result {
	t.Helper()
	results, err := service.LoadBulkPlan(strings.NewReader(csvText), h.logPath)
	if err != nil {
		t.Fatalf("LoadBulkPlan: %v", err)
	}
	return results
}

func (h *bulkHarness) logCount(t *testing.T) int {
	t.Helper()
	records, err := issuancelog.ReadLog(h.logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	return len(records)
}

func statuses(results []bulk.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Status
	}
	return out
}

func assertStatuses(t *testing.T, results []bulk.Result, want ...string) {
	t.Helper()
	got := statuses(results)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("statuses = %v, want %v", got, want)
	}
}

const threeRowCSV = "name,honor,detail,date\n" +
	"Alice,Other,Service,2026-03-14\n" +
	"Bob,Appointment,Advisor,2026-03-14\n" +
	"Dave,Other,Help,2026-03-14\n"

// TestBulkSign_ConfirmCancelClearsBusy: the confirm dialog lists counts,
// preview names and invalid lines; Cancel re-enables the tab without
// launching a worker.
func TestBulkSign_ConfirmCancelClearsBusy(t *testing.T) {
	h := newBulkUIHarness(t)
	results := h.plan(t, "name,honor,detail,date\nAlice,Other,Service,2026-03-14\nBad,Nope,X,2026-03-14\n")

	confirmBulkSign(h.deps, results)
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	for _, want := range []string{"2 rows: 1 to sign, 0 already issued, 1 invalid", "First names to be signed:", "Alice", "line 3: honor"} {
		if !strings.Contains(texts, want) {
			t.Errorf("confirm dialog missing %q in:\n%s", want, texts)
		}
	}
	tapOverlayButton(t, h.w, "Cancel")
	if h.lastBusy(t) {
		t.Error("expected setBusy(false) after Cancel")
	}
	if h.launches != 0 || h.opens != 0 {
		t.Errorf("launches=%d opens=%d, want 0", h.launches, h.opens)
	}
}

// TestBulkSign_ConfirmSignRunsBatch drives confirm → worker → summary with a
// cached PIN and fake adapter, then closes the summary.
func TestBulkSign_ConfirmSignRunsBatch(t *testing.T) {
	h := newBulkUIHarness(t)
	results := h.plan(t, threeRowCSV)

	confirmBulkSign(h.deps, results)
	tapOverlayButton(t, h.w, "Sign")

	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusSigned, bulk.StatusSigned)
	if n := h.logCount(t); n != 3 {
		t.Errorf("audit log has %d records, want 3", n)
	}
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Processed 3 rows: 3 successful (3 newly signed, 0 already issued)") {
		t.Errorf("summary missing tally:\n%s", texts)
	}
	if strings.Contains(texts, "Cancelled.") || strings.Contains(texts, "Batch stopped") {
		t.Errorf("unexpected stop message:\n%s", texts)
	}
	if findButton(t, topOverlay(t, h.w), "Export Results CSV…") == nil {
		t.Error("summary has no export button")
	}
	if len(h.busy) != 0 {
		t.Errorf("setBusy called before summary was closed: %v", h.busy)
	}
	tapOverlayButton(t, h.w, "Close")
	if h.lastBusy(t) {
		t.Error("expected setBusy(false) after closing summary")
	}
	if top := h.w.Canvas().Overlays().Top(); top != nil {
		t.Error("progress or summary dialog left open")
	}
}

// TestBulkSign_CancelDuringBatch taps the progress dialog's Cancel while the
// first row is signing: that row finishes, the rest are not attempted, and
// the summary reports the cancellation.
func TestBulkSign_CancelDuringBatch(t *testing.T) {
	h := newBulkUIHarness(t)
	results := h.plan(t, threeRowCSV)

	inner := h.deps.openAdapter
	h.deps.openAdapter = func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		if h.opens == 0 {
			top := topOverlay(t, h.w)
			if !strings.Contains(strings.Join(labelTexts(t, top), "\n"), "Signing 1 of 3: Alice") {
				t.Errorf("progress label not updated: %v", labelTexts(t, top))
			}
			b := findButton(t, top, "Cancel")
			if b == nil {
				t.Fatal("progress dialog has no Cancel button")
			}
			test.Tap(b)
			if !b.Disabled() {
				t.Error("Cancel button not disabled after tap")
			}
			if !strings.Contains(strings.Join(labelTexts(t, top), "\n"), "Stopping after current row…") {
				t.Errorf("stopping label not shown: %v", labelTexts(t, top))
			}
		}
		return inner(rp)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runBulkSignWorker(ctx, cancel, h.deps, results)

	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Cancelled.") {
		t.Errorf("summary missing cancellation:\n%s", texts)
	}
}

// TestBulkSign_NothingToSignGoesToSummary: with no to_sign rows there is no
// confirm step and no PIN/worker; the summary is shown directly.
func TestBulkSign_NothingToSignGoesToSummary(t *testing.T) {
	h := newBulkUIHarness(t)
	results := h.plan(t, "name,honor,detail,date\nBad,Nope,X,2026-03-14\n")

	confirmBulkSign(h.deps, results)
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Processed 1 rows: 0 successful") || !strings.Contains(texts, "Re-open the same file") {
		t.Errorf("unexpected summary:\n%s", texts)
	}
	// With nothing signable the confirm dialog is skipped, so the summary
	// must carry the per-row reasons.
	if !strings.Contains(texts, "Invalid rows (skipped):") || !strings.Contains(texts, "line 2: honor: not one of the allowed honor titles") {
		t.Errorf("summary missing invalid-row reasons:\n%s", texts)
	}
	if h.launches != 0 {
		t.Errorf("launches = %d, want 0", h.launches)
	}
}

// TestBulkSign_StopErrorShownInSummary: a failing row stops the batch and
// the summary carries the stop reason.
func TestBulkSign_StopErrorShownInSummary(t *testing.T) {
	h := newBulkUIHarness(t)
	h.newSigner = func(k ed25519.PrivateKey) core.SigningAdapter { return &authErrSignAdapter{secretKey: k} }
	results := h.plan(t, threeRowCSV)

	ctx, cancel := context.WithCancel(context.Background())
	runBulkSignWorker(ctx, cancel, h.deps, results)

	assertStatuses(t, results, bulk.StatusFailed, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Batch stopped: Incorrect PIN") {
		t.Errorf("summary missing stop reason:\n%s", texts)
	}
	if _, ok := h.deps.pinCache.Get(); ok {
		t.Error("PIN cache not cleared after auth error")
	}
}

// fakeURIReader is a fyne.URIReadCloser over an in-memory string.
type fakeURIReader struct {
	io.Reader
	closed bool
}

func (f *fakeURIReader) Close() error  { f.closed = true; return nil }
func (f *fakeURIReader) URI() fyne.URI { return storage.NewFileURI("/tmp/in.csv") }

// TestBulkSign_FileChosen covers the file-open callback: dismiss or error
// clears busy; a parse error is shown and clears busy; a good file closes
// the reader and reaches the confirm dialog.
func TestBulkSign_FileChosen(t *testing.T) {
	t.Run("dismissed", func(t *testing.T) {
		h := newBulkUIHarness(t)
		onBulkFileChosen(h.deps, nil, nil)
		if h.lastBusy(t) || h.launches != 0 {
			t.Errorf("busy=%v launches=%d, want false/0", h.busy, h.launches)
		}
	})
	t.Run("dialog error", func(t *testing.T) {
		h := newBulkUIHarness(t)
		r := &fakeURIReader{Reader: strings.NewReader(threeRowCSV)}
		onBulkFileChosen(h.deps, r, errors.New("boom"))
		if h.lastBusy(t) || h.launches != 0 {
			t.Errorf("busy=%v launches=%d, want false/0", h.busy, h.launches)
		}
	})
	t.Run("parse error", func(t *testing.T) {
		h := newBulkUIHarness(t)
		r := &fakeURIReader{Reader: strings.NewReader("")}
		onBulkFileChosen(h.deps, r, nil)
		if !r.closed {
			t.Error("reader not closed")
		}
		if h.lastBusy(t) {
			t.Error("expected setBusy(false) after load error")
		}
		topOverlay(t, h.w) // error dialog
	})
	t.Run("ok", func(t *testing.T) {
		h := newBulkUIHarness(t)
		r := &fakeURIReader{Reader: strings.NewReader(threeRowCSV)}
		onBulkFileChosen(h.deps, r, nil)
		if !r.closed {
			t.Error("reader not closed")
		}
		if len(h.busy) != 0 {
			t.Errorf("unexpected setBusy calls: %v", h.busy)
		}
		if findButton(t, topOverlay(t, h.w), "Sign") == nil {
			t.Error("confirm dialog not shown")
		}
	})
}

// fakeURIWriter is a fyne.URIWriteCloser whose URI points at path. Exports
// that write by path (bulk results) ignore buf; the issuance-log export writes
// through Write into buf. failWrite / failClose make Write / Close fail.
type fakeURIWriter struct {
	path      string
	buf       bytes.Buffer
	failWrite bool
	failClose bool
	closed    bool
}

func (f *fakeURIWriter) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("write failed")
	}
	return f.buf.Write(p)
}
func (f *fakeURIWriter) Close() error {
	f.closed = true
	if f.failClose {
		return errors.New("close failed")
	}
	return nil
}
func (f *fakeURIWriter) URI() fyne.URI { return storage.NewFileURI(f.path) }

// TestBulkSign_Export covers the summary's export button and the save
// callback: dismissed, save-dialog error, success, and write failure.
func TestBulkSign_Export(t *testing.T) {
	h := newBulkUIHarness(t)
	results := h.plan(t, threeRowCSV)
	showBulkSummary(h.deps, results, nil)
	tapOverlayButton(t, h.w, "Export Results CSV…")
	tapOverlayButton(t, h.w, "Cancel") // dismiss the save dialog: nil writer

	before := len(h.w.Canvas().Overlays().List())
	onBulkExportChosen(h.deps, results, nil, nil)
	if n := len(h.w.Canvas().Overlays().List()); n != before {
		t.Fatalf("cancel changed overlay count %d → %d", before, n)
	}

	// Fyne reports an uncreatable destination as a writer plus a non-nil error.
	onBulkExportChosen(h.deps, results, &fakeURIWriter{}, errors.New("boom"))
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(strings.ToLower(texts), "failed to save results file") {
		t.Errorf("save-dialog error not shown:\n%s", texts)
	}
	tapOverlayButton(t, h.w, "OK")

	path := filepath.Join(t.TempDir(), "results.csv")
	w := &fakeURIWriter{path: path}
	onBulkExportChosen(h.deps, results, w, nil)
	if !w.closed {
		t.Error("writer not closed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("results not written: %v", err)
	}
	if !strings.Contains(string(got), "name,honor,detail,date,url,status,error") || !strings.Contains(string(got), "Alice") {
		t.Errorf("unexpected CSV:\n%s", got)
	}

	bad := &fakeURIWriter{path: filepath.Join(t.TempDir(), "missing", "r.csv")}
	onBulkExportChosen(h.deps, results, bad, nil)
	if !bad.closed {
		t.Error("writer not closed on failure")
	}
	texts = strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(strings.ToLower(texts), "failed to save results file") {
		t.Errorf("error dialog not shown:\n%s", texts)
	}
}

// TestBulkSign_OpenDialogShownAndBusy: tapping the entry point marks the tab
// busy and shows a file-open dialog. The dialog itself is not driven.
func TestBulkSign_OpenDialogShownAndBusy(t *testing.T) {
	h := newBulkUIHarness(t)
	startBulkSign(h.deps)
	if !h.lastBusy(t) {
		t.Error("expected setBusy(true)")
	}
	topOverlay(t, h.w)
}

// TestSignTab_BulkButtonAndBusyToggle: the Sign tab exposes the bulk entry
// point below Sign Credential, and starting a bulk run disables both.
func TestSignTab_BulkButtonAndBusyToggle(t *testing.T) {
	test.NewTempApp(t)
	w := test.NewWindow(nil)
	w.Resize(fyne.NewSize(800, 600))
	defer w.Close()

	dir := t.TempDir()
	form, cleanup := NewSignTab(SignTabConfig{LogPath: filepath.Join(dir, "log.json"), DataDir: dir}, w)
	defer cleanup()
	w.SetContent(container.NewStack(form))

	signBtn := findButton(t, form, "Sign Credential")
	bulkBtn := findButton(t, form, "Bulk Sign from File…")
	if signBtn == nil || bulkBtn == nil {
		t.Fatalf("buttons missing: sign=%v bulk=%v", signBtn, bulkBtn)
	}
	idx := func(o fyne.CanvasObject) int {
		for i, c := range form.Objects {
			if c == o {
				return i
			}
		}
		return -1
	}
	if idx(bulkBtn) != idx(signBtn)+1 {
		t.Errorf("bulk button at %d, want directly below sign button at %d", idx(bulkBtn), idx(signBtn))
	}

	test.Tap(bulkBtn)
	if !signBtn.Disabled() || !bulkBtn.Disabled() {
		t.Errorf("after bulk tap: sign disabled=%v bulk disabled=%v, want both", signBtn.Disabled(), bulkBtn.Disabled())
	}
	tapOverlayButton(t, w, "Cancel")
	if signBtn.Disabled() || bulkBtn.Disabled() {
		t.Errorf("after file dialog cancel: sign disabled=%v bulk disabled=%v, want neither", signBtn.Disabled(), bulkBtn.Disabled())
	}
}
