// Package gui provides the Fyne-based graphical interface for the RHG Authenticator.
package gui

import (
	"context"
	"fmt"
	"io"
	"os"
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
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/safego"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// SignTabConfig holds the dependencies for the sign tab.
type SignTabConfig struct {
	LogPath string
	DataDir string
	Keyring ghapi.Keyring    // for issue reporting (may be nil)
	Logger  *debuglog.Logger // shared app diagnostic log (nil → no-op)
}

// NewSignTab creates the credential signing tab UI. The returned cleanup
// function must be called on application shutdown to securely clear the
// PIN cache.
func NewSignTab(config SignTabConfig, window fyne.Window) (*fyne.Container, func()) {
	logger := config.Logger
	pinCache := yubikey.NewPinCache()

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Full name of recipient")

	honorSelect := widget.NewSelect(service.HonorTitles, nil)
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

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		a, err := yubikey.NewYubiKeyAdapter(readPin)
		if err != nil {
			return nil, nil, err
		}
		return a, a, nil
	}

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

		// Trim all text inputs before validation and use.
		recipient := core.TrimJS(recipientEntry.Text)
		honor := core.TrimJS(honorSelect.Selected)
		detail := core.TrimJS(detailEntry.Text)
		date := core.TrimJS(dateEntry.Text)

		// Validate form.
		if err := service.ValidateSignForm(recipient, honor, detail, date); err != nil {
			statusLabel.SetText(err.Error())
			return
		}

		setBusy(true)
		statusLabel.SetText("Preparing to sign...")

		req := core.SignRequest{
			Recipient: recipient,
			Honor:     honor,
			Detail:    detail,
			Date:      date,
		}

		safego.Go(func() {
			defer fyne.Do(func() { setBusy(false) })

			// Set after the PIN is resolved (Item 1 prompts before Open), so the
			// "Connecting" status doesn't show while the PIN dialog is up.
			onConnecting := func() {
				fyne.Do(func() { statusLabel.SetText("Connecting to YubiKey...") })
			}

			result, err := service.ExecuteSignFlow(req, config.LogPath, openAdapter, MakePinReader(window, pinCache), onConnecting, logger)
			if err != nil {
				service.ClearPINCacheOnAuthError(err, pinCache)
				fyne.Do(func() {
					msg := service.SignFlowErrorMessage(err, logger)
					statusLabel.SetText(msg)
					if service.OfferIssueReport(err) && config.Keyring != nil {
						var reportBtn *widget.Button
						reportBtn = widget.NewButton("Report Issue", func() {
							// Keychain read + GitHub calls: off the UI thread,
							// with the button disabled until they finish.
							reportBtn.Disable()
							reportBtn.SetText("Reporting…")
							title := errorreport.BuildIssueTitle("signing", msg)
							body := service.SignIssueBody(err, msg)
							safego.Go(func() {
								resultURL := ""
								// Deferred so the button comes back even if the
								// report panics (safego recovers it).
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
								resultURL, _ = errorreport.ReportIssue(ctx, config.Keyring, config.DataDir, title, body)
								fyne.Do(func() {
									if resultURL == "" {
										return
									}
									// Only open https://github.com URLs; anything else is not ours.
									if u := parseGitHubURL(resultURL); u != nil {
										fyne.CurrentApp().OpenURL(u)
									} else {
										logger.Log("Report Issue: refusing to open non-GitHub URL: " + core.SanitizeForLog(resultURL))
									}
								})
							})
						})
						resultContainer.Add(reportBtn)
					}
				})
				return
			}

			fyne.Do(func() {
				if result.Existing {
					statusLabel.SetText("Credential previously generated.")
					dialog.ShowInformation("Already Issued", "Credential previously generated, no new record created.", window)
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
					defaultName := service.BuildFilename(req.Date, result.Hash8, "svg")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							logger.Log("SVG save failed: " + core.SanitizeForLog(err.Error()))
							showSaveError(window, "SVG file")
							return
						}
						if writer == nil {
							return
						}
						defer writer.Close()
						svg, saveErr := qr.GenerateSVG(result.Response.URL)
						if saveErr == nil {
							saveErr = os.WriteFile(writer.URI().Path(), svg, 0o644)
						}
						if saveErr != nil {
							logger.Log("SVG save failed: " + core.SanitizeForLog(saveErr.Error()))
							showSaveError(window, "SVG file")
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".svg"}))
					setDialogLocation(saveDialog)
					saveDialog.Show()
				})

				savePNGButton := widget.NewButton("Save PNG", func() {
					defaultName := service.BuildFilename(req.Date, result.Hash8, "png")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil {
							logger.Log("PNG save failed: " + core.SanitizeForLog(err.Error()))
							showSaveError(window, "PNG file")
							return
						}
						if writer == nil {
							return
						}
						defer writer.Close()
						pngHiRes, pngErr := qr.GeneratePNG(result.Response.URL, service.QRSavePx)
						if pngErr != nil {
							logger.Log("PNG generation failed: " + core.SanitizeForLog(pngErr.Error()))
							dialog.ShowError(fmt.Errorf("failed to generate PNG"), window)
							return
						}
						if writeErr := os.WriteFile(writer.URI().Path(), pngHiRes, 0o644); writeErr != nil {
							logger.Log("PNG save failed: " + core.SanitizeForLog(writeErr.Error()))
							showSaveError(window, "PNG file")
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".png"}))
					setDialogLocation(saveDialog)
					saveDialog.Show()
				})

				copyURLButton := widget.NewButton("Copy URL", func() {
					fyne.CurrentApp().Clipboard().SetContent(result.Response.URL)
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
			window:      window,
			logPath:     config.LogPath,
			launchGo:    safego.Go,
			openAdapter: openAdapter,
			pinCache:    pinCache,
			logger:      logger,
			setBusy:     setBusy,
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

	return form, func() { pinCache.Close() }
}

// reportIssueTimeout bounds the Report Issue keychain read and GitHub calls.
const reportIssueTimeout = 30 * time.Second
