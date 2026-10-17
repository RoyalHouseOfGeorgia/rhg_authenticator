package gui

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// bulkSignDeps holds what the bulk sign UI flow needs from the Sign tab.
type bulkSignDeps struct {
	window   fyne.Window
	app      *service.App
	events   *Events
	launchGo func(func())
	setBusy  func(bool) // UI thread only
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
	setDialogLocation(openDialog)
	openDialog.Show()
}

// onBulkFileChosen is the file-open callback: it loads and plans the CSV on
// the worker, then shows the confirm dialog. UI thread only.
func onBulkFileChosen(d bulkSignDeps, reader fyne.URIReadCloser, err error) {
	if err != nil || reader == nil {
		d.setBusy(false)
		return
	}
	path := reader.URI().Path()
	_ = reader.Close()
	d.launchGo(func() {
		plan, loadErr := d.app.LoadBulk(path)
		if loadErr != nil {
			fyne.Do(func() {
				dialog.ShowError(loadErr, d.window)
				d.setBusy(false)
			})
			return
		}
		fyne.Do(func() { confirmBulkSign(d, plan) })
	})
}

// confirmBulkSign shows what is about to be signed and, on confirmation,
// launches the signing worker. With nothing to sign it goes straight to the
// worker, which returns the summary without a PIN prompt. UI thread only.
func confirmBulkSign(d bulkSignDeps, plan service.BulkPlan) {
	if plan.ToSign == 0 {
		d.launchGo(func() { runBulkSignWorker(d, plan) })
		return
	}

	items := []fyne.CanvasObject{
		widget.NewLabel(plan.CountsLine),
		widget.NewLabel("First names to be signed:"),
	}
	for _, name := range plan.PreviewNames {
		items = append(items, widget.NewLabel("  "+name))
	}
	if len(plan.InvalidLines) > 0 {
		items = append(items, invalidRowsView("Invalid rows (will be skipped):", plan.InvalidLines)...)
	}

	dialog.NewCustomConfirm("Bulk Sign", "Sign", "Cancel", container.NewVBox(items...), func(ok bool) {
		if !ok {
			d.setBusy(false)
			return
		}
		d.launchGo(func() { runBulkSignWorker(d, plan) })
	}, d.window).Show()
}

// runBulkSignWorker signs the batch on the worker goroutine and then shows
// the summary. The progress dialog is only ever touched on the UI thread
// (event handlers run inside fyne.Do).
func runBulkSignWorker(d bulkSignDeps, plan service.BulkPlan) {
	var (
		progress    dialog.Dialog
		progressBar *widget.ProgressBar
		statusLabel *widget.Label
		stopping    bool
	)

	d.events.On(service.EventBulkConnecting, func(any) {
		progressBar = widget.NewProgressBar()
		statusLabel = widget.NewLabel("Connecting to YubiKey...")
		statusLabel.Wrapping = fyne.TextWrapWord
		var cancelButton *widget.Button
		cancelButton = widget.NewButton("Cancel", func() {
			d.app.CancelBulk()
			stopping = true
			cancelButton.Disable()
			statusLabel.SetText("Stopping after current row…")
		})
		content := container.NewVBox(progressBar, statusLabel, cancelButton)
		progress = dialog.NewCustomWithoutButtons("Bulk Sign", content, d.window)
		progress.Show()
	})

	// The service emits EventBulkConnecting before any EventBulkProgress and
	// fyne.Do runs handlers in order, so progressBar and statusLabel are set.
	d.events.On(service.EventBulkProgress, func(payload any) {
		p, ok := payload.(service.BulkProgress)
		if !ok {
			return
		}
		progressBar.SetValue(float64(p.Done) / float64(p.Total))
		if !stopping {
			statusLabel.SetText(fmt.Sprintf("Signing %d of %d: %s — touch your YubiKey if it is blinking", p.Done+1, p.Total, p.Name))
		}
	})

	outcome, err := d.app.RunBulk(context.Background())

	fyne.Do(func() {
		if progress != nil {
			progress.Hide()
		}
		if err != nil {
			dialog.ShowError(err, d.window)
			d.setBusy(false)
			return
		}
		showBulkSummary(d, plan, outcome)
	})
}

// showBulkSummary shows the batch outcome with a results-CSV export. Closing
// it re-enables the Sign tab. UI thread only.
func showBulkSummary(d bulkSignDeps, plan service.BulkPlan, outcome service.BulkOutcome) {
	items := []fyne.CanvasObject{}
	summary := widget.NewLabel(outcome.SummaryLine)
	summary.Wrapping = fyne.TextWrapWord
	items = append(items, summary)
	if outcome.StopMessage != "" {
		stop := widget.NewLabel(outcome.StopMessage)
		stop.Wrapping = fyne.TextWrapWord
		items = append(items, stop)
	}
	if len(plan.InvalidLines) > 0 {
		items = append(items, invalidRowsView("Invalid rows (skipped):", plan.InvalidLines)...)
	}

	exportButton := widget.NewButton("Export Results CSV…", func() {
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			onBulkExportChosen(d, writer, err)
		}, d.window)
		saveDialog.SetFileName(service.BulkResultsFilename(time.Now()))
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
		setDialogLocation(saveDialog)
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

// onBulkExportChosen is the results-CSV save callback: it writes the CSV on
// the worker. UI thread only.
func onBulkExportChosen(d bulkSignDeps, writer fyne.URIWriteCloser, err error) {
	if err != nil {
		stdlog.Printf("bulk results save failed: %s", core.SanitizeForLog(err.Error()))
		dialog.ShowError(fmt.Errorf("failed to save results file"), d.window)
		return
	}
	if writer == nil {
		return
	}
	path := writer.URI().Path()
	_ = writer.Close()
	d.launchGo(func() {
		// ExportBulkResults logs its own write failures.
		if saveErr := d.app.ExportBulkResults(path); saveErr != nil {
			fyne.Do(func() { dialog.ShowError(fmt.Errorf("failed to save results file"), d.window) })
		}
	})
}
