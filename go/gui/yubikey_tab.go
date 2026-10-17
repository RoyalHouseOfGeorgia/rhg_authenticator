package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewYubiKeyTab creates the YubiKey registry check tab UI.
func NewYubiKeyTab(app *service.App) *fyne.Container {
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	resultArea := container.NewVBox()

	checkBtn := widget.NewButton("Check YubiKey", nil)

	checkBtn.OnTapped = func() {
		resultArea.RemoveAll()
		statusLabel.SetText("Checking...")
		checkBtn.Disable()
		safego.Go(func() {
			result, err := app.CheckYubiKey()
			fyne.Do(func() {
				checkBtn.Enable()
				if err != nil {
					statusLabel.SetText(err.Error())
					return
				}
				statusLabel.SetText(result.Status)
				for _, line := range result.Details {
					resultArea.Add(widget.NewLabel(line))
				}
			})
		})
	}

	if !app.Info().Online {
		checkBtn.Disable()
		statusLabel.SetText("Registry unavailable — connect to internet to check key")
	}

	topBar := container.NewBorder(nil, nil, nil, nil, container.NewBorder(nil, nil, checkBtn, nil, statusLabel))
	return container.NewBorder(topBar, nil, nil, nil, resultArea)
}
