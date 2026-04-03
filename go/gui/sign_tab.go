// Package gui provides the Fyne-based graphical interface for the RHG Authenticator.
package gui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
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

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// honorTitles are the available credential honor designations.
var honorTitles = []string{
	"Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ",
	"Order of the St. Queen Tamar of Georgia",
	"Order of the Crown of Georgia",
	"Medal of Merit of the Royal House of Georgia",
	"Ennoblement",
}

// SignTabConfig holds the dependencies for the sign tab.
type SignTabConfig struct {
	LogPath string
	DataDir string
	Keyring ghapi.Keyring  // for issue reporting (may be nil)
	SafeGo  func(func())  // panic-safe goroutine launcher (may be nil — falls back to plain go)
}

// QR code output sizes.
const (
	qrPreviewPx = 512
	qrSavePx    = 2048
)

// NewSignTab creates the credential signing tab UI. The returned cleanup
// function must be called on application shutdown to securely clear the
// PIN cache.
func NewSignTab(config SignTabConfig, window fyne.Window) (*fyne.Container, func()) {
	logger := debuglog.New(filepath.Join(config.DataDir, "debug.log"))
	pinCache := yubikey.NewPinCache()

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Full name of recipient")

	honorSelect := widget.NewSelect(honorTitles, nil)
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

	var signButton *widget.Button
	signButton = widget.NewButton("Sign Credential", func() {
		// Clear previous results.
		resultContainer.RemoveAll()

		// Trim all text inputs before validation and use.
		recipient := strings.TrimSpace(recipientEntry.Text)
		honor := strings.TrimSpace(honorSelect.Selected)
		detail := strings.TrimSpace(detailEntry.Text)
		date := strings.TrimSpace(dateEntry.Text)

		// Validate form.
		if err := validateSignForm(recipient, honor, detail, date); err != nil {
			statusLabel.SetText(err.Error())
			return
		}

		signButton.Disable()
		statusLabel.SetText("Connecting to YubiKey...")

		req := core.SignRequest{
			Recipient: recipient,
			Honor:     honor,
			Detail:    detail,
			Date:      date,
		}

		launchGo := func(fn func()) { go fn() }
		if config.SafeGo != nil {
			launchGo = config.SafeGo
		}
		launchGo(func() {
			defer fyne.Do(func() { signButton.Enable() })

			openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
				a, err := yubikey.NewYubiKeyAdapter(readPin)
				if err != nil {
					return nil, nil, err
				}
				return a, a, nil
			}

			result, err := executeSignFlow(req, config.LogPath, openAdapter, MakePinReader(window, pinCache), logger)
			if err != nil {
				fyne.Do(func() {
					msg := signFlowErrorMessage(err, logger)
					statusLabel.SetText(msg)
					// Offer "Report Issue" for real errors, not cancellations.
					if !strings.Contains(err.Error(), ErrSigningCancelled.Error()) && config.Keyring != nil {
						reportBtn := widget.NewButton("Report Issue", func() {
							title := errorreport.BuildIssueTitle("signing", msg)
							body := errorreport.BuildIssueBody(buildinfo.Version, "signing", err.Error(), logger.Path())
							resultURL, _ := errorreport.ReportIssue(context.Background(), config.Keyring, config.DataDir, title, body)
							if resultURL != "" {
								if u, parseErr := url.Parse(resultURL); parseErr == nil {
									fyne.CurrentApp().OpenURL(u)
								}
							}
						})
						resultContainer.Add(reportBtn)
					}
				})
				return
			}

			fyne.Do(func() {
				statusLabel.SetText("Signed successfully.")

				// QR preview image.
				qrImage := canvas.NewImageFromResource(
					fyne.NewStaticResource("qr-preview.png", result.PNGPreview),
				)
				qrImage.FillMode = canvas.ImageFillContain
				qrImage.SetMinSize(fyne.NewSize(256, 256))

				printAdvisory := widget.NewLabel("Print QR at minimum 3\u00d73 cm")
				printAdvisory.Alignment = fyne.TextAlignCenter

				saveSVGButton := widget.NewButton("Save SVG", func() {
					defaultName := buildFilename(req.Date, result.Hash8, "svg")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						if saveErr := qr.SaveSVG(result.Response.URL, writer.URI().Path()); saveErr != nil {
							logger.Log("SVG save failed: " + saveErr.Error())
							dialog.ShowError(fmt.Errorf("failed to save SVG file"), window)
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".svg"}))
					saveDialog.Show()
				})

				savePNGButton := widget.NewButton("Save PNG", func() {
					defaultName := buildFilename(req.Date, result.Hash8, "png")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						pngHiRes, pngErr := qr.GeneratePNG(result.Response.URL, qrSavePx)
						if pngErr != nil {
							logger.Log("PNG generation failed: " + pngErr.Error())
							dialog.ShowError(fmt.Errorf("failed to generate PNG"), window)
							return
						}
						if writeErr := os.WriteFile(writer.URI().Path(), pngHiRes, 0o600); writeErr != nil {
							logger.Log("PNG save failed: " + writeErr.Error())
							dialog.ShowError(fmt.Errorf("failed to save PNG file"), window)
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".png"}))
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
		statusLabel,
		resultContainer,
	)

	return form, func() { pinCache.Close() }
}

// validateSignForm checks that all required sign form fields are filled and valid.
func validateSignForm(recipient, honor, detail, date string) error {
	if strings.TrimSpace(recipient) == "" {
		return fmt.Errorf("recipient is required")
	}
	if honor == "" {
		return fmt.Errorf("honor title must be selected")
	}
	if strings.TrimSpace(detail) == "" {
		return fmt.Errorf("detail is required")
	}
	if !core.IsValidDate(date) {
		return fmt.Errorf("date must be in YYYY-MM-DD format and be a valid calendar date")
	}
	return nil
}

// sanitizeError returns a generic description for hardware-related errors,
// stripping implementation details that could leak hardware configuration.
func sanitizeError(prefix string, err error) string {
	if err == nil {
		return prefix + ": unknown error"
	}
	switch core.ClassifyHardwareError(err) {
	case core.HwErrSmartcard:
		return prefix + ": smart card service error"
	case core.HwErrPIN:
		return prefix + ": PIN error"
	case core.HwErrHardware:
		return prefix + ": hardware device error"
	default:
		return prefix + ": unexpected error"
	}
}

// friendlyYubiKeyError returns a user-friendly error message for YubiKey
// connection failures.
func friendlyYubiKeyError(err error, logger *debuglog.Logger) string {
	if err == nil {
		return "Unknown YubiKey error"
	}
	// Always log the actual error for diagnosis.
	logger.Log("yubikey: " + core.SanitizeForLog(err.Error()))
	switch core.ClassifyHardwareError(err) {
	case core.HwErrSmartcard:
		return "Smart card service not available. On macOS this is built-in; on Windows check the Smart Card service is running."
	case core.HwErrHardware:
		return "YubiKey not detected. Ensure the key is plugged in."
	default:
		return "Failed to connect to YubiKey. Check debug.log for details."
	}
}

// signFlowErrorMessage maps an error from executeSignFlow to a user-friendly
// status message.
func signFlowErrorMessage(err error, logger *debuglog.Logger) string {
	// User cancelled the PIN dialog — not an error.
	// Use string match because piv-go wraps PINPrompt errors with %v,
	// breaking the errors.Is chain for our sentinel.
	if strings.Contains(err.Error(), ErrSigningCancelled.Error()) {
		return ""
	}
	var sfe *SignFlowError
	if errors.As(err, &sfe) {
		switch sfe.Phase {
		case PhaseExportKey:
			return "Failed to read YubiKey. Check debug.log for details."
		case PhaseQR:
			return "QR generation failed. Check debug.log for details."
		case PhaseSign:
			logger.Log(sfe.Error())
			return "Signing failed. Check debug.log for details."
		default:
			logger.Log(sfe.Error())
			return "Unexpected error. Check debug.log for details."
		}
	}
	// Adapter open failures arrive here (not wrapped in SignFlowError).
	// Check certificate/slot errors first — the YubiKey WAS detected but
	// the slot is empty or has the wrong key type. These errors may also
	// contain "smart card" from piv-go, which would misclassify as
	// HwErrHardware ("YubiKey not detected") if checked later.
	errMsg := err.Error()
	logger.Log("sign flow: " + core.SanitizeForLog(errMsg))
	if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "slot 9c") {
		return "No signing certificate found on YubiKey (PIV slot 9c). Generate an Ed25519 key first."
	}
	if core.ClassifyHardwareError(err) != "" {
		return friendlyYubiKeyError(err, logger)
	}
	return "Signing failed. Check debug.log for details."
}

// buildFilename constructs a default filename for saving QR code output.
// Format: rhg-credential-<date>-<hash8>-<suffix>.<ext>
// where suffix is "min3cm" for SVG and "2048px" for PNG.
func buildFilename(date, hash8, ext string) string {
	suffix := "min3cm"
	if ext == "png" {
		suffix = "2048px"
	}
	return fmt.Sprintf("rhg-credential-%s-%s-%s.%s", date, hash8, suffix, ext)
}

