package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
)

// fyneLastFolderKey mirrors Fyne's unexported lastFolderKey (fyne
// dialog/file.go): the folder any file dialog was last in. A rename upstream
// is caught by TestSetDialogLocation_FallsBackToDesktop.
const fyneLastFolderKey = "fyne:fileDialogLastFolder"

// desktopDir returns the user's Desktop folder (on Windows, wherever the shell
// says it is, e.g. OneDrive\Desktop) as a dialog start location.
func desktopDir() (fyne.ListableURI, bool) {
	p := desktopPath()
	if p == "" {
		return nil, false
	}
	desktop, err := storage.ListerForURI(storage.NewFileURI(p))
	if err != nil {
		return nil, false
	}
	return desktop, true
}

// setDialogLocation opens d in the last folder a file dialog was in, falling
// back to the Desktop on first run or when that folder no longer exists.
func setDialogLocation(d *dialog.FileDialog) {
	if u, err := storage.ParseURI(fyne.CurrentApp().Preferences().String(fyneLastFolderKey)); err == nil {
		if last, err := storage.ListerForURI(u); err == nil {
			d.SetLocation(last)
			return
		}
	}
	if desktop, ok := desktopDir(); ok {
		d.SetLocation(desktop)
	}
}
