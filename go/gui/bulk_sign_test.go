package gui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// bulkUIHarness wires bulkSignDeps to a test window, a synchronous launcher
// and an offline service.App, so RunBulk never reaches the card.
type bulkUIHarness struct {
	w        fyne.Window
	busy     []bool
	launches int
	prompter *cancelPrompter
	deps     bulkSignDeps
}

func newBulkUIHarness(t *testing.T) *bulkUIHarness {
	t.Helper()
	test.NewTempApp(t)
	w := test.NewWindow(nil)
	w.Resize(fyne.NewSize(800, 600))
	t.Cleanup(w.Close)

	h := &bulkUIHarness{w: w, prompter: &cancelPrompter{}}
	events := NewEvents()
	h.deps = bulkSignDeps{
		window:   w,
		app:      newTestApp(t, events, h.prompter),
		events:   events,
		launchGo: func(fn func()) { h.launches++; fn() },
		setBusy:  func(b bool) { h.busy = append(h.busy, b) },
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

// writeCSV writes text to a temp CSV file and returns its path.
func writeCSV(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.csv")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// load plans csvText in the harness app.
func (h *bulkUIHarness) load(t *testing.T, csvText string) service.BulkPlan {
	t.Helper()
	plan, err := h.deps.app.LoadBulk(writeCSV(t, csvText))
	if err != nil {
		t.Fatalf("LoadBulk: %v", err)
	}
	return plan
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
	plan := h.load(t, "name,honor,detail,date\nAlice,Other,Service,2026-03-14\nBad,Nope,X,2026-03-14\n")

	confirmBulkSign(h.deps, plan)
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
	if h.launches != 0 || h.prompter.calls != 0 {
		t.Errorf("launches=%d prompts=%d, want 0", h.launches, h.prompter.calls)
	}
}

// scriptedRun is a bulkService whose RunBulk stands in for a run on a card:
// it emits the service's connecting and first progress events, runs during
// (if set), and returns outcome; CancelBulk is recorded. LoadBulk and
// ExportBulkResults are the embedded real App's.
type scriptedRun struct {
	bulkService
	events    *Events
	during    func()
	outcome   service.BulkOutcome
	runs      int
	cancelled bool
}

func (s *scriptedRun) RunBulk(context.Context) (service.BulkOutcome, error) {
	s.runs++
	s.events.Emit(service.EventBulkConnecting, nil)
	s.events.Emit(service.EventBulkProgress, service.BulkProgress{Done: 0, Total: 3, Name: "Alice"})
	if s.during != nil {
		s.during()
	}
	return s.outcome, nil
}

func (s *scriptedRun) CancelBulk() { s.cancelled = true }

// TestBulkSign_ConfirmSignRunsBatch drives confirm → worker → summary.
// Closing the summary clears busy.
func TestBulkSign_ConfirmSignRunsBatch(t *testing.T) {
	h := newBulkUIHarness(t)
	plan := h.load(t, threeRowCSV)
	run := &scriptedRun{bulkService: h.deps.app, events: h.deps.events,
		outcome: service.BulkOutcome{SummaryLine: "Processed 3 rows: 3 successful (3 newly signed, 0 already issued), 0 invalid, 0 failed/not attempted.", Stopped: service.BulkCompleted}}
	h.deps.app = run

	confirmBulkSign(h.deps, plan)
	tapOverlayButton(t, h.w, "Sign")

	if run.runs != 1 {
		t.Errorf("runs = %d, want 1", run.runs)
	}
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Processed 3 rows: 3 successful") || strings.Contains(texts, "Signing 1 of 3") {
		t.Errorf("unexpected summary, or the progress dialog left open:\n%s", texts)
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
		t.Error("summary dialog left open")
	}
}

// TestBulkSign_CancelDuringBatch drives the progress dialog through the
// service events: connecting shows it, progress updates the label, Cancel
// stops the run and freezes the label, and the summary reports the
// cancellation with the progress dialog gone.
func TestBulkSign_CancelDuringBatch(t *testing.T) {
	h := newBulkUIHarness(t)
	h.load(t, threeRowCSV)
	run := &scriptedRun{bulkService: h.deps.app, events: h.deps.events,
		outcome: service.BulkOutcome{SummaryLine: "Processed 3 rows: 0 successful", StopMessage: "Cancelled.", Stopped: service.BulkCancelled}}
	h.deps.app = run

	run.during = func() {
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
		if !run.cancelled {
			t.Error("Cancel did not cancel the run")
		}
		h.deps.events.Emit(service.EventBulkProgress, service.BulkProgress{Done: 1, Total: 3, Name: "Bob"})
		texts := strings.Join(labelTexts(t, top), "\n")
		if !strings.Contains(texts, "Stopping after current row…") || strings.Contains(texts, "Bob") {
			t.Errorf("stopping label not kept: %v", texts)
		}
	}

	runBulkSignWorker(h.deps, service.BulkPlan{})

	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Cancelled.") || strings.Contains(texts, "Stopping after current row…") {
		t.Errorf("summary missing cancellation or progress dialog left open:\n%s", texts)
	}
}

// TestBulkSign_NothingToSignGoesToSummary: with no to_sign rows there is no
// confirm step and no PIN prompt; the real service run's summary (offline is
// fine with nothing to sign) is shown directly, and closing it clears busy.
func TestBulkSign_NothingToSignGoesToSummary(t *testing.T) {
	h := newBulkUIHarness(t)
	plan := h.load(t, "name,honor,detail,date\nBad,Nope,X,2026-03-14\n")

	confirmBulkSign(h.deps, plan)
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Processed 1 rows: 0 successful") || !strings.Contains(texts, "Re-open the same file") {
		t.Errorf("unexpected summary:\n%s", texts)
	}
	// With nothing signable the confirm dialog is skipped, so the summary
	// must carry the per-row reasons.
	if !strings.Contains(texts, "Invalid rows (skipped):") || !strings.Contains(texts, "line 2: honor: not one of the allowed honor titles") {
		t.Errorf("summary missing invalid-row reasons:\n%s", texts)
	}
	if h.prompter.calls != 0 {
		t.Errorf("prompts = %d, want 0", h.prompter.calls)
	}
	if len(h.busy) != 0 {
		t.Errorf("setBusy called before summary was closed: %v", h.busy)
	}
	tapOverlayButton(t, h.w, "Close")
	if h.lastBusy(t) {
		t.Error("expected setBusy(false) after closing summary")
	}
}

// TestBulkSign_StopErrorShownInSummary: the summary carries the stop reason.
func TestBulkSign_StopErrorShownInSummary(t *testing.T) {
	h := newBulkUIHarness(t)
	showBulkSummary(h.deps, service.BulkPlan{}, service.BulkOutcome{SummaryLine: "Processed 3 rows", StopMessage: "Batch stopped: Incorrect PIN",
		FailedLines: []string{"line 3: This YubiKey's key is not in the registry"}})
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, "Batch stopped: Incorrect PIN") {
		t.Errorf("summary missing stop reason:\n%s", texts)
	}
	if !strings.Contains(texts, "Failed rows:") || !strings.Contains(texts, "line 3: This YubiKey's key is not in the registry") {
		t.Errorf("summary missing the failed rows:\n%s", texts)
	}
}

// TestBulkSign_RunErrorShownAndClearsBusy: a run refused by the service
// (no plan loaded) shows the error and re-enables the tab.
func TestBulkSign_RunErrorShownAndClearsBusy(t *testing.T) {
	h := newBulkUIHarness(t)
	runBulkSignWorker(h.deps, service.BulkPlan{})
	if h.lastBusy(t) {
		t.Error("expected setBusy(false) after a run error")
	}
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, service.ErrNoBulkPlan.Error()) {
		t.Errorf("error dialog not shown:\n%s", texts)
	}
}

// TestBulkSign_OfflineConfirmThenRunRefused: offline, the file still loads
// and the confirm shows the plan, but Sign shows the service's offline error
// without a PIN prompt and re-enables the tab.
func TestBulkSign_OfflineConfirmThenRunRefused(t *testing.T) {
	h := newBulkUIHarness(t) // its registry is unreachable
	plan := h.load(t, threeRowCSV)
	confirmBulkSign(h.deps, plan)
	tapOverlayButton(t, h.w, "Sign")
	if h.prompter.calls != 0 {
		t.Errorf("prompts = %d, want 0", h.prompter.calls)
	}
	if h.lastBusy(t) {
		t.Error("expected setBusy(false) after the refusal")
	}
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(texts, service.ErrOffline.Error()) {
		t.Errorf("offline error not shown:\n%s", texts)
	}
}

// fakeURIReader is a fyne.URIReadCloser whose URI points at path.
type fakeURIReader struct {
	io.Reader
	path   string
	closed bool
}

func (f *fakeURIReader) Close() error  { f.closed = true; return nil }
func (f *fakeURIReader) URI() fyne.URI { return storage.NewFileURI(f.path) }

func newFakeURIReader(path string) *fakeURIReader {
	return &fakeURIReader{Reader: strings.NewReader(""), path: path}
}

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
		r := newFakeURIReader(writeCSV(t, threeRowCSV))
		onBulkFileChosen(h.deps, r, errors.New("boom"))
		if h.lastBusy(t) || h.launches != 0 {
			t.Errorf("busy=%v launches=%d, want false/0", h.busy, h.launches)
		}
	})
	t.Run("parse error", func(t *testing.T) {
		h := newBulkUIHarness(t)
		r := newFakeURIReader(writeCSV(t, ""))
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
		r := newFakeURIReader(writeCSV(t, threeRowCSV))
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

// TestBulkSign_Export covers the summary's export button and the save
// callback: dismissed, save-dialog error, success, and write failure.
func TestBulkSign_Export(t *testing.T) {
	h := newBulkUIHarness(t)
	h.load(t, threeRowCSV)
	showBulkSummary(h.deps, service.BulkPlan{}, service.BulkOutcome{SummaryLine: "Processed 3 rows", ResultsFilename: "rhg-bulk-results-2026-03-14-101500.csv"})
	tapOverlayButton(t, h.w, "Export Results CSV…")
	if names := entryTexts(t, topOverlay(t, h.w)); !slices.Contains(names, "rhg-bulk-results-2026-03-14-101500.csv") {
		t.Errorf("save dialog file name entries = %q, want the outcome's ResultsFilename", names)
	}
	tapOverlayButton(t, h.w, "Cancel") // dismiss the save dialog: nil writer

	before := len(h.w.Canvas().Overlays().List())
	onBulkExportChosen(h.deps, nil, nil)
	if n := len(h.w.Canvas().Overlays().List()); n != before {
		t.Fatalf("cancel changed overlay count %d → %d", before, n)
	}

	// Fyne reports an uncreatable destination as a writer plus a non-nil error.
	onBulkExportChosen(h.deps, &fakeURIWriter{}, errors.New("boom"))
	texts := strings.Join(labelTexts(t, topOverlay(t, h.w)), "\n")
	if !strings.Contains(strings.ToLower(texts), "failed to save results file") {
		t.Errorf("save-dialog error not shown:\n%s", texts)
	}
	tapOverlayButton(t, h.w, "OK")

	path := filepath.Join(t.TempDir(), "results.csv")
	w := &fakeURIWriter{path: path}
	onBulkExportChosen(h.deps, w, nil)
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
	onBulkExportChosen(h.deps, bad, nil)
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

	events := NewEvents()
	form := NewSignTab(newTestApp(t, events, &cancelPrompter{}), events, w)
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
