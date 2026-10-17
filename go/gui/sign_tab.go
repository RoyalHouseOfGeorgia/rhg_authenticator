// Package gui provides the Fyne-based graphical interface for the RHG Authenticator.
package gui

import (
	"context"
	"errors"
	stdlog "log"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	xwidget "fyne.io/x/fyne/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewSignTab creates the credential signing tab UI. events must be the
// *Events passed as Config.Events to service.New.
func NewSignTab(app *service.App, events *Events, window fyne.Window) *fyne.Container {
	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Full name of recipient")

	honorSelect := widget.NewSelect(app.Honors(), nil)
	honorSelect.PlaceHolder = "Select honor title"

	detailEntry := widget.NewMultiLineEntry()
	detailEntry.SetPlaceHolder("Specific distinction or rank")

	dateEntry := widget.NewEntry()
	dateEntry.SetText(time.Now().UTC().Format("2006-01-02"))
	dateEntry.Disable() // read-only — date set via calendar

	calButton := widget.NewButton("\U0001F4C5", func() {
		cal := xwidget.NewCalendar(time.Now().UTC(), func(t time.Time) {
			dateEntry.SetText(t.Format("2006-01-02"))
		})
		dialog.ShowCustom("Select Date", "Close", cal, window)
	})

	dateRow := container.NewBorder(nil, nil, nil, calButton, dateEntry)

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	// Container for QR preview and action buttons (shown after signing).
	resultContainer := container.NewVBox()

	// Emitted after the PIN is resolved, so the "Connecting" status doesn't
	// show while the PIN dialog is up.
	events.On(service.EventSignConnecting, func(any) { statusLabel.SetText("Connecting to YubiKey...") })

	var signButton, bulkButton *widget.Button
	// setBusy disables or enables both signing entry points. UI thread only.
	setBusy := func(busy bool) {
		if busy {
			signButton.Disable()
			bulkButton.Disable()
		} else {
			signButton.Enable()
			bulkButton.Enable()
		}
	}

	signButton = widget.NewButton("Sign Credential", func() {
		// Clear previous results.
		resultContainer.RemoveAll()

		fields := service.SignFields{
			Recipient: recipientEntry.Text,
			Honor:     honorSelect.Selected,
			Detail:    detailEntry.Text,
			Date:      dateEntry.Text,
		}

		if err := fields.Validate(); err != nil {
			statusLabel.SetText(err.Error())
			return
		}

		setBusy(true)
		statusLabel.SetText("Preparing to sign...")

		safego.Go(func() {
			defer fyne.Do(func() { setBusy(false) })

			result, err := app.Sign(context.Background(), fields)
			if err != nil {
				msg := err.Error()
				var se *service.SignError
				if errors.As(err, &se) {
					msg = se.Message
				}
				fyne.Do(func() {
					statusLabel.SetText(msg)
					if se != nil && se.OfferReport {
						resultContainer.Add(newReportIssueButton(app, se))
					}
				})
				return
			}

			fyne.Do(func() {
				if result.Existing {
					statusLabel.SetText("Credential previously generated.")
					dialog.ShowInformation("Already Issued", "Credential previously generated, no new record created.", window)
				} else if result.Warning != "" {
					statusLabel.SetText(result.Warning)
					dialog.ShowInformation("Not Recorded", result.Warning, window)
				} else {
					statusLabel.SetText("Signed successfully.")
				}

				// QR preview image.
				qrImage := canvas.NewImageFromResource(
					fyne.NewStaticResource("qr-preview.png", result.PNGPreview),
				)
				qrImage.FillMode = canvas.ImageFillContain
				qrImage.SetMinSize(fyne.NewSize(256, 256))

				printAdvisory := widget.NewLabel("Print QR at minimum 3\u00d73 cm")
				printAdvisory.Alignment = fyne.TextAlignCenter

				saveSVGButton := widget.NewButton("Save SVG", func() {
					showSaveQRDialog(app, window, result.URL, "svg", service.BuildFilename(result.Date, result.Hash8, "svg"))
				})
				savePNGButton := widget.NewButton("Save PNG", func() {
					showSaveQRDialog(app, window, result.URL, "png", service.BuildFilename(result.Date, result.Hash8, "png"))
				})

				copyURLButton := widget.NewButton("Copy URL", func() {
					fyne.CurrentApp().Clipboard().SetContent(result.URL)
				})

				actionButtons := container.NewHBox(saveSVGButton, savePNGButton, copyURLButton)

				resultContainer.Add(qrImage)
				resultContainer.Add(printAdvisory)
				resultContainer.Add(actionButtons)
				resultContainer.Refresh()
			})
		})
	})

	bulkButton = widget.NewButton("Bulk Sign from File…", func() {
		startBulkSign(bulkSignDeps{
			window:   window,
			app:      app,
			events:   events,
			launchGo: safego.Go,
			setBusy:  setBusy,
		})
	})

	form := container.NewVBox(
		widget.NewLabel("Recipient"),
		recipientEntry,
		widget.NewLabel("Honor"),
		honorSelect,
		widget.NewLabel("Detail"),
		detailEntry,
		widget.NewLabel("Date"),
		dateRow,
		layout.NewSpacer(),
		signButton,
		bulkButton,
		statusLabel,
		resultContainer,
	)

	return form
}

// newReportIssueButton returns a "Report Issue" button that files se.
// UI thread only.
func newReportIssueButton(app *service.App, se *service.SignError) *widget.Button {
	var reportBtn *widget.Button
	reportBtn = widget.NewButton("Report Issue", func() {
		// Keychain read + GitHub calls: off the UI thread, with the button
		// disabled until they finish.
		reportBtn.Disable()
		reportBtn.SetText("Reporting…")
		safego.Go(func() {
			resultURL := ""
			// Deferred so the button comes back even if the report panics
			// (safego recovers it).
			defer fyne.Do(func() {
				reportBtn.SetText("Report Issue")
				if strings.Contains(resultURL, "/issues/new") || resultURL == "" {
					reportBtn.Enable() // browser form or failure: allow another try
				} else {
					reportBtn.SetText("Issue Reported") // filed via API: no duplicates
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), reportIssueTimeout)
			defer cancel()
			resultURL, _ = app.ReportSignError(ctx, se)
			// Only https://github.com URLs are returned; parse for OpenURL.
			if u := ghapi.ParseGitHubURL(resultURL); u != nil {
				fyne.Do(func() { fyne.CurrentApp().OpenURL(u) })
			}
		})
	})
	return reportBtn
}

// showSaveQRDialog asks where to save the QR code for url as format ("svg"
// or "png"). UI thread only.
func showSaveQRDialog(app *service.App, window fyne.Window, url, format, defaultName string) {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		onSaveQRChosen(app, window, url, format, writer, err)
	}, window)
	saveDialog.SetFileName(defaultName)
	saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{"." + format}))
	setDialogLocation(saveDialog)
	saveDialog.Show()
}

// onSaveQRChosen is the QR save-dialog callback. UI thread only.
func onSaveQRChosen(app *service.App, window fyne.Window, url, format string, writer fyne.URIWriteCloser, err error) {
	what := strings.ToUpper(format) + " file"
	if err != nil {
		stdlog.Printf("%s save failed: %s", strings.ToUpper(format), core.SanitizeForLog(err.Error()))
		showSaveError(window, what)
		return
	}
	if writer == nil {
		return // cancelled
	}
	path := writer.URI().Path()
	_ = writer.Close()
	// SaveQR logs its own failures.
	if err := app.SaveQR(url, format, path); err != nil {
		showSaveError(window, what)
	}
}

// reportIssueTimeout bounds the Report Issue keychain read and GitHub calls.
const reportIssueTimeout = 30 * time.Second
