package gui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// bulkPreviewNames is how many to_sign recipient names the confirm dialog
// shows, so the operator can spot a mis-encoded file before signing.
const bulkPreviewNames = 5

// bulkSignDeps holds what the bulk sign UI flow needs from the Sign tab.
type bulkSignDeps struct {
	window      fyne.Window
	logPath     string
	launchGo    func(func())
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error)
	pinCache    *yubikey.PinCache
	logger      *debuglog.Logger
	setBusy     func(bool) // UI thread only
}

// startBulkSign runs the bulk sign flow: pick a CSV, confirm, sign, summarize.
// It must be called on the UI thread. Dialog callbacks only launch work via
// launchGo; file reading, planning, PIN entry and signing run on the worker,
// and the worker touches the UI only through fyne.Do.
func startBulkSign(d bulkSignDeps) {
	d.setBusy(true)
	openDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		onBulkFileChosen(d, reader, err)
	}, d.window)
	openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
	openDialog.Show()
}

// onBulkFileChosen is the file-open callback: it loads and plans the CSV on
// the worker, then shows the confirm dialog. UI thread only.
func onBulkFileChosen(d bulkSignDeps, reader fyne.URIReadCloser, err error) {
	if err != nil || reader == nil {
		d.setBusy(false)
		return
	}
	d.launchGo(func() {
		results, loadErr := loadBulkPlan(reader, d.logPath)
		_ = reader.Close()
		if loadErr != nil {
			fyne.Do(func() {
				dialog.ShowError(loadErr, d.window)
				d.setBusy(false)
			})
			return
		}
		fyne.Do(func() { confirmBulkSign(d, results) })
	})
}

// confirmBulkSign shows what is about to be signed and, on confirmation,
// launches the signing worker. UI thread only.
func confirmBulkSign(d bulkSignDeps, results []bulk.Result) {
	if bulk.Summarize(results).ToSign == 0 {
		showBulkSummary(d, results, nil)
		return
	}

	counts, preview, invalid := bulkConfirmText(results)
	items := []fyne.CanvasObject{
		widget.NewLabel(counts),
		widget.NewLabel("First names to be signed:"),
	}
	for _, name := range preview {
		items = append(items, widget.NewLabel("  "+name))
	}
	if len(invalid) > 0 {
		items = append(items, invalidRowsView("Invalid rows (will be skipped):", invalid)...)
	}

	dialog.NewCustomConfirm("Bulk Sign", "Sign", "Cancel", container.NewVBox(items...), func(ok bool) {
		if !ok {
			d.setBusy(false)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		d.launchGo(func() { runBulkSignWorker(ctx, cancel, d, results) })
	}, d.window).Show()
}

// runBulkSignWorker signs the batch on the worker goroutine and then shows
// the summary. The progress dialog is only ever touched inside fyne.Do.
func runBulkSignWorker(ctx context.Context, cancel context.CancelFunc, d bulkSignDeps, results []bulk.Result) {
	var (
		progress    dialog.Dialog
		progressBar *widget.ProgressBar
		statusLabel *widget.Label
	)

	onConnecting := func() {
		fyne.Do(func() {
			progressBar = widget.NewProgressBar()
			statusLabel = widget.NewLabel("Connecting to YubiKey...")
			statusLabel.Wrapping = fyne.TextWrapWord
			var cancelButton *widget.Button
			cancelButton = widget.NewButton("Cancel", func() {
				cancel()
				cancelButton.Disable()
				statusLabel.SetText("Stopping after current row…")
			})
			content := container.NewVBox(progressBar, statusLabel, cancelButton)
			progress = dialog.NewCustomWithoutButtons("Bulk Sign", content, d.window)
			progress.Show()
		})
	}

	onProgress := func(done, total int, name string) {
		fyne.Do(func() {
			progressBar.SetValue(float64(done) / float64(total))
			if ctx.Err() == nil {
				statusLabel.SetText(fmt.Sprintf("Signing %d of %d: %s — touch your YubiKey if it is blinking", done+1, total, name))
			}
		})
	}

	err := runBulkFlow(ctx, results, d.logPath, d.openAdapter, MakePinReader(d.window, d.pinCache), onConnecting, onProgress, d.logger)
	clearPINCacheOnAuthError(err, d.pinCache)
	cancel()

	fyne.Do(func() {
		if progress != nil {
			progress.Hide()
		}
		showBulkSummary(d, results, err)
	})
}

// showBulkSummary shows the batch outcome with a results-CSV export. Closing
// it re-enables the Sign tab. UI thread only.
func showBulkSummary(d bulkSignDeps, results []bulk.Result, stopErr error) {
	items := []fyne.CanvasObject{}
	summary := widget.NewLabel(bulkSummaryLine(bulk.Summarize(results)))
	summary.Wrapping = fyne.TextWrapWord
	items = append(items, summary)
	if msg := bulkStopMessage(stopErr, d.logger); msg != "" {
		stop := widget.NewLabel(msg)
		stop.Wrapping = fyne.TextWrapWord
		items = append(items, stop)
	}
	if _, _, invalid := bulkConfirmText(results); len(invalid) > 0 {
		items = append(items, invalidRowsView("Invalid rows (skipped):", invalid)...)
	}

	exportButton := widget.NewButton("Export Results CSV…", func() {
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			onBulkExportChosen(d, results, writer, err)
		}, d.window)
		saveDialog.SetFileName(bulkResultsFilename(time.Now()))
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
		saveDialog.Show()
	})
	items = append(items, exportButton, widget.NewLabel("Re-open the same file to regenerate results later."))

	summaryDialog := dialog.NewCustom("Bulk Sign — Results", "Close", container.NewVBox(items...), d.window)
	summaryDialog.SetOnClosed(func() { d.setBusy(false) })
	summaryDialog.Show()
}

// invalidRowsView renders "line N: reason" entries under a heading in a
// scrollable area. A single label keeps a 500-row file cheap to lay out.
func invalidRowsView(heading string, invalid []string) []fyne.CanvasObject {
	lbl := widget.NewLabel(strings.Join(invalid, "\n"))
	lbl.Wrapping = fyne.TextWrapWord
	scroll := container.NewVScroll(lbl)
	scroll.SetMinSize(fyne.NewSize(480, 150))
	return []fyne.CanvasObject{widget.NewLabel(heading), scroll}
}

// onBulkExportChosen is the results-CSV save callback. UI thread only.
func onBulkExportChosen(d bulkSignDeps, results []bulk.Result, writer fyne.URIWriteCloser, err error) {
	if err != nil {
		d.logger.Log("bulk results save failed: " + core.SanitizeForLog(err.Error()))
		dialog.ShowError(fmt.Errorf("failed to save results file"), d.window)
		return
	}
	if writer == nil {
		return
	}
	defer writer.Close()
	if saveErr := saveBulkResults(writer.URI().Path(), results); saveErr != nil {
		d.logger.Log("bulk results save failed: " + core.SanitizeForLog(saveErr.Error()))
		dialog.ShowError(fmt.Errorf("failed to save results file"), d.window)
	}
}

// saveBulkResults renders results as CSV and writes them to path.
func saveBulkResults(path string, results []bulk.Result) error {
	var buf bytes.Buffer
	if err := bulk.WriteResultCSV(&buf, results); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// bulkSummaryLine formats the per-status tally shown after a batch.
func bulkSummaryLine(c bulk.Counts) string {
	return fmt.Sprintf("Processed %d rows: %d successful (%d newly signed, %d already issued), %d invalid, %d failed/not attempted.",
		c.Total, c.Successful(), c.Signed, c.AlreadyIssued, c.Invalid, c.Failed+c.NotAttempted)
}

// bulkConfirmText returns the confirm dialog's counts line, up to
// bulkPreviewNames to_sign recipient names, and one "line N: <error>" entry
// per invalid row.
func bulkConfirmText(results []bulk.Result) (counts string, preview []string, invalid []string) {
	c := bulk.Summarize(results)
	counts = fmt.Sprintf("%d rows: %d to sign, %d already issued, %d invalid", c.Total, c.ToSign, c.AlreadyIssued, c.Invalid)
	for _, r := range results {
		switch r.Status {
		case bulk.StatusToSign:
			if len(preview) < bulkPreviewNames {
				preview = append(preview, r.Req.Recipient)
			}
		case bulk.StatusInvalid:
			invalid = append(invalid, fmt.Sprintf("line %d: %s", r.Line, r.Err))
		}
	}
	return counts, preview, invalid
}

// bulkResultsFilename returns the default export name for a results CSV,
// timestamped in UTC.
func bulkResultsFilename(t time.Time) string {
	return t.UTC().Format("rhg-bulk-results-2006-01-02-150405.csv")
}
