package gui

import (
	"errors"
	stdlog "log"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// OnErrorLogExportTapped reads the diagnostic log at logPath and offers a
// save dialog (default: Desktop, rhg-error-log-<local date>.log). The log is
// read before the dialog opens because Fyne truncates the destination before
// the save callback runs.
func OnErrorLogExportTapped(logPath string, window fyne.Window) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		stdlog.Printf("errorlog: failed to read log for export: %s", core.SanitizeForLog(err.Error()))
		dialog.ShowError(errors.New("could not read the error log"), window)
		return
	}
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		onErrorLogExportChosen(data, window, writer, err)
	}, window)
	saveDialog.SetFileName(time.Now().Format("rhg-error-log-2006-01-02.log"))
	saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".log"}))
	if desktop, ok := desktopDir(); ok {
		saveDialog.SetLocation(desktop)
	}
	saveDialog.Show()
}

// onErrorLogExportChosen is the save-dialog callback for the error log export:
// it writes data (the log bytes read at click time) through the writer Fyne
// opened.
func onErrorLogExportChosen(data []byte, window fyne.Window, writer fyne.URIWriteCloser, err error) {
	// Fyne reports an uncreatable destination as a writer plus a non-nil
	// error, so err must be checked before writer.
	if err != nil {
		stdlog.Printf("errorlog: export save failed: %s", core.SanitizeForLog(err.Error()))
		showSaveError(window, "error log")
		return
	}
	if writer == nil {
		return // cancelled
	}
	_, werr := writer.Write(data)
	cerr := writer.Close()
	if werr != nil || cerr != nil {
		stdlog.Printf("errorlog: export write failed: %s", core.SanitizeForLog(errors.Join(werr, cerr).Error()))
		showSaveError(window, "error log")
		return
	}
	dialog.ShowInformation("Error Log Exported",
		"Saved to:\n"+filepath.FromSlash(writer.URI().Path())+
			"\n\nYou can attach this file to an email. It contains app diagnostics"+
			" (may include your GitHub username and file paths) — no PINs or keys.", window)
}

// ShowErrorWithLogExport shows an error dialog with an "Export Error Log…"
// button next to OK. Export is the confirm role and OK the dismiss role, so
// Escape or closing the dialog never triggers an export.
func ShowErrorWithLogExport(title, msg, logPath string, window fyne.Window) {
	dialog.NewCustomConfirm(title, "Export Error Log…", "OK", widget.NewLabel(msg), func(export bool) {
		if export {
			OnErrorLogExportTapped(logPath, window)
		}
	}, window).Show()
}
