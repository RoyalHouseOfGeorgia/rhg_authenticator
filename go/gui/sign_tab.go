// Package gui provides the Fyne-based graphical interface for the RHG Authenticator.
package gui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
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
	Registry core.Registry
	LogPath  string
}

// NewSignTab creates the credential signing tab UI.
func NewSignTab(config SignTabConfig, window fyne.Window) *fyne.Container {
	pinCache := yubikey.NewPinCache()

	recipientEntry := widget.NewEntry()
	recipientEntry.SetPlaceHolder("Full name of recipient")

	honorSelect := widget.NewSelect(honorTitles, nil)
	honorSelect.PlaceHolder = "Select honor title"

	detailEntry := widget.NewMultiLineEntry()
	detailEntry.SetPlaceHolder("Specific distinction or rank")

	dateEntry := widget.NewEntry()
	dateEntry.SetPlaceHolder("YYYY-MM-DD")
	dateEntry.SetText(time.Now().Format("2006-01-02"))

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

			adapter, err := yubikey.NewYubiKeyAdapter(MakePinReader(window, pinCache))
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText(friendlyYubiKeyError(err))
				})
				return
			}
			defer adapter.Close()

			pubKey, err := adapter.ExportPublicKey()
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("Error: " + err.Error())
				})
				return
			}

			authority, err := registry.FindMatchingAuthority(config.Registry, pubKey)
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("YubiKey public key not found in registry")
				})
				return
			}

			fyne.Do(func() {
				statusLabel.SetText("Signing...")
			})

			resp, err := core.HandleSign(req, adapter, pubKey, authority, config.LogPath)
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("Error: " + err.Error())
				})
				return
			}

			// QR is generated at 512px for preview and 2048px for save. These are
			// separate operations because the save resolution is much higher.
			pngData, err := qr.GeneratePNG(resp.URL, 512)
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("QR generation error: " + err.Error())
				})
				return
			}

			// Compute hash8 for filenames.
			hash8, err := computeHash8(resp.Payload)
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("Hash computation error: " + err.Error())
				})
				return
			}

			fyne.Do(func() {
				statusLabel.SetText("Signed successfully.")

				// QR preview image.
				qrImage := canvas.NewImageFromResource(
					fyne.NewStaticResource("qr-preview.png", pngData),
				)
				qrImage.FillMode = canvas.ImageFillContain
				qrImage.SetMinSize(fyne.NewSize(256, 256))

				printAdvisory := widget.NewLabel("Print QR at minimum 3\u00d73 cm")
				printAdvisory.Alignment = fyne.TextAlignCenter

				saveSVGButton := widget.NewButton("Save SVG", func() {
					defaultName := buildFilename(req.Date, hash8, "svg")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						if saveErr := qr.SaveSVG(resp.URL, writer.URI().Path()); saveErr != nil {
							dialog.ShowError(saveErr, window)
						}
					}, window)
					saveDialog.SetFileName(defaultName)
					saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".svg"}))
					saveDialog.Show()
				})

				savePNGButton := widget.NewButton("Save PNG", func() {
					defaultName := buildFilename(req.Date, hash8, "png")
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						pngHiRes, pngErr := qr.GeneratePNG(resp.URL, 2048)
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
					window.Clipboard().SetContent(resp.URL)
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
		dateEntry,
		layout.NewSpacer(),
		signButton,
		statusLabel,
		resultContainer,
	)

	return form
}

// validateSignForm checks that all required sign form fields are filled and valid.
func validateSignForm(recipient, honor, detail, date string) error {
	if strings.TrimSpace(recipient) == "" {
		return fmt.Errorf("Recipient is required")
	}
	if honor == "" {
		return fmt.Errorf("Honor title must be selected")
	}
	if strings.TrimSpace(detail) == "" {
		return fmt.Errorf("Detail is required")
	}
	if !core.IsValidDate(date) {
		return fmt.Errorf("Date must be in YYYY-MM-DD format and be a valid calendar date")
	}
	return nil
}

// computeHash8 returns the first 8 hex characters of the SHA-256 hash of the
// decoded payload bytes. The payload is base64url-encoded canonical JSON.
func computeHash8(payloadB64 string) (string, error) {
	payloadBytes, err := core.Decode(payloadB64)
	if err != nil {
		return "", fmt.Errorf("decoding payload: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	return hex.EncodeToString(sum[:])[:8], nil
}

// friendlyYubiKeyError returns a user-friendly error message for YubiKey
// connection failures.
func friendlyYubiKeyError(err error) string {
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "pcsc") || strings.Contains(lower, "scard"):
		return "Smart card service not available. On Linux: sudo apt install pcscd"
	case strings.Contains(lower, "yubikey") || strings.Contains(lower, "card"):
		return "Please plug in your YubiKey and try again"
	default:
		return "Failed to connect to YubiKey.\n\nDetails: " + err.Error()
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

