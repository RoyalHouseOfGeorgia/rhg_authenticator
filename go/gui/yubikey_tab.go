package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewYubiKeyTab creates the YubiKey registry check tab UI.
func NewYubiKeyTab(reg core.Registry, online bool, window fyne.Window) *fyne.Container {
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	resultArea := container.NewVBox()

	checkBtn := widget.NewButton("Check YubiKey", nil)

	checkBtn.OnTapped = func() {
		resultArea.RemoveAll()
		statusLabel.SetText("Checking...")
		checkBtn.Disable()
		safego.Go(func() {
			result := service.CheckYubiKey(reg)
			fyne.Do(func() {
				checkBtn.Enable()
				status, details := service.FormatKeyResult(result)
				statusLabel.SetText(status)
				for _, line := range details {
					resultArea.Add(widget.NewLabel(line))
				}
			})
		})
	}

	if !online {
		checkBtn.Disable()
		statusLabel.SetText("Registry unavailable — connect to internet to check key")
	}

	topBar := container.NewBorder(nil, nil, nil, nil, container.NewBorder(nil, nil, checkBtn, nil, statusLabel))
	return container.NewBorder(topBar, nil, nil, nil, resultArea)
}
