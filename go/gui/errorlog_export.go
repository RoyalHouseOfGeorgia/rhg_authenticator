package gui

import (
	"errors"
	stdlog "log"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// OnErrorLogExportTapped reads the diagnostic log with export
// (App.ErrorLogExport) and offers a save dialog (last-used folder, else
// Desktop; rhg-error-log-<local date>.log). The log is read before the dialog
// opens because Fyne truncates the destination before the save callback runs.
func OnErrorLogExportTapped(export func() ([]byte, error), window fyne.Window) {
	data, err := export()
	if err != nil {
		dialog.ShowError(err, window)
		return
	}
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		onErrorLogExportChosen(data, window, writer, err)
	}, window)
	saveDialog.SetFileName(time.Now().Format("rhg-error-log-2006-01-02.log"))
	saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".log"}))
	setDialogLocation(saveDialog)
	saveDialog.Show()
}

// onErrorLogExportChosen is the save-dialog callback for the error log export:
// it writes data (the log bytes read at click time) through the writer Fyne
// opened.
func onErrorLogExportChosen(data []byte, window fyne.Window, writer fyne.URIWriteCloser, err error) {
	if !writeExport(data, window, writer, err, "error log") {
		return
	}
	dialog.ShowInformation("Error Log Exported",
		"Saved to:\n"+filepath.FromSlash(writer.URI().Path())+
			"\n\nYou can attach this file to an email. It contains app diagnostics"+
			" (may include your GitHub username and file paths) — no PINs or keys.", window)
}

// writeExport writes data through the writer a save dialog opened and reports
// whether it was saved; a failure shows the save error for what (e.g. "error
// log"), and a cancel shows nothing.
func writeExport(data []byte, window fyne.Window, writer fyne.URIWriteCloser, err error, what string) bool {
	// Fyne reports an uncreatable destination as a writer plus a non-nil
	// error, so err must be checked before writer.
	if err != nil {
		stdlog.Printf("%s export save failed: %s", what, core.SanitizeForLog(err.Error()))
		showSaveError(window, what)
		return false
	}
	if writer == nil {
		return false // cancelled
	}
	_, werr := writer.Write(data)
	cerr := writer.Close()
	if werr != nil || cerr != nil {
		stdlog.Printf("%s export write failed: %s", what, core.SanitizeForLog(errors.Join(werr, cerr).Error()))
		showSaveError(window, what)
		return false
	}
	return true
}

// showSaveError reports a failed save of what (e.g. "issuance log") and points
// macOS users at the Files and Folders permission, the usual cause of a failed
// save to a protected folder (Desktop, Documents, Downloads).
func showSaveError(window fyne.Window, what string) {
	dialog.ShowError(errors.New("could not save the "+what+" — on a Mac, check System Settings → Privacy & Security → Files and Folders"), window)
}

// ShowErrorWithLogExport shows an error dialog with an "Export Error Log…"
// button next to OK; Export reads the log with export (App.ErrorLogExport).
// Export is the confirm role and OK the dismiss role, so Escape or closing the
// dialog never triggers an export.
func ShowErrorWithLogExport(title, msg string, export func() ([]byte, error), window fyne.Window) {
	dialog.NewCustomConfirm(title, "Export Error Log…", "OK", widget.NewLabel(msg), func(ok bool) {
		if ok {
			OnErrorLogExportTapped(export, window)
		}
	}, window).Show()
}
