package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
)

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
