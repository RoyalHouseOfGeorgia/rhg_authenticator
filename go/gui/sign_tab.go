// Package gui provides the Fyne-based graphical interface for the RHG Authenticator.
package gui

import (
	"fmt"
	"io"
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

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
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
}

// QR code output sizes.
const (
	qrPreviewPx = 512
	qrSavePx    = 2048
)

// debugLogger appends timestamped messages to a log file. A nil or
// zero-value logger silently discards all messages.
type debugLogger struct {
	path string
}

func (d *debugLogger) log(msg string) {
	if d == nil || d.path == "" {
		return
	}
	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().UTC().Format(time.RFC3339), msg)
}

// NewSignTab creates the credential signing tab UI. The returned cleanup
// function must be called on application shutdown to securely clear the
// PIN cache.
func NewSignTab(config SignTabConfig, window fyne.Window) (*fyne.Container, func()) {
	logger := &debugLogger{path: filepath.Join(config.DataDir, "debug.log")}
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
		cal := xwidget.NewCalendar(time.Now(), func(t time.Time) {
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

		// Validate form.
		if err := validateSignForm(recipientEntry.Text, honorSelect.Selected, detailEntry.Text, dateEntry.Text); err != nil {
			statusLabel.SetText(err.Error())
			return
		}

		signButton.Disable()
		statusLabel.SetText("Connecting to YubiKey...")

		req := core.SignRequest{
			Recipient: recipientEntry.Text,
			Honor:     honorSelect.Selected,
			Detail:    detailEntry.Text,
			Date:      dateEntry.Text,
		}

		go func() {
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
					statusLabel.SetText(signFlowErrorMessage(err, logger))
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
							dialog.ShowError(saveErr, window)
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
							dialog.ShowError(pngErr, window)
							return
						}
						if writeErr := os.WriteFile(writer.URI().Path(), pngHiRes, 0o600); writeErr != nil {
							dialog.ShowError(writeErr, window)
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".png"}))
					saveDialog.Show()
				})

				copyURLButton := widget.NewButton("Copy URL", func() {
					window.Clipboard().SetContent(result.Response.URL)
				})

				actionButtons := container.NewHBox(saveSVGButton, savePNGButton, copyURLButton)

				resultContainer.Add(qrImage)
				resultContainer.Add(printAdvisory)
				resultContainer.Add(actionButtons)
				resultContainer.Refresh()
			})
		}()
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
	switch classifyHardwareError(err) {
	case hwErrSmartcard:
		return prefix + ": smart card service error"
	case hwErrPIN:
		return prefix + ": PIN error"
	case hwErrHardware:
		return prefix + ": hardware device error"
	default:
		return prefix + ": unexpected error"
	}
}

// friendlyYubiKeyError returns a user-friendly error message for YubiKey
// connection failures.
func friendlyYubiKeyError(err error, logger *debugLogger) string {
	if err == nil {
		return "Unknown YubiKey error"
	}
	switch classifyHardwareError(err) {
	case hwErrSmartcard:
		return "Smart card service not available. On Linux: sudo apt install pcscd"
	case hwErrHardware:
		return "Please plug in your YubiKey and try again"
	default:
		logger.log("YubiKey: " + err.Error())
		return "Failed to connect to YubiKey. Check debug.log for details."
	}
}

// signFlowErrorMessage maps an error from executeSignFlow to a user-friendly
// status message.
func signFlowErrorMessage(err error, logger *debugLogger) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "export public key:"):
		return "Failed to read YubiKey. Check debug.log for details."
	case strings.HasPrefix(msg, "QR generation:"):
		return "QR generation failed. Check debug.log for details."
	case strings.HasPrefix(msg, "sign:"):
		logger.log(msg)
		return "Signing failed. Check debug.log for details."
	default:
		if classifyHardwareError(err) != "" {
			return friendlyYubiKeyError(err, logger)
		}
		logger.log("sign flow: " + msg)
		return "Signing failed. Check debug.log for details."
	}
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

