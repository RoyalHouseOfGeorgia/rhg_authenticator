package gui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// KeyCheckResult holds the result of a YubiKey registry check.
type KeyCheckResult struct {
	Found       bool
	Fingerprint string         // SHA-256 hex of raw 32-byte public key
	Entry       *core.KeyEntry // non-nil if Found
	Error       error          // non-nil if check failed
}

// checkYubiKey opens a YubiKey adapter, reads the public key, computes its
// fingerprint, and searches the registry for a matching entry.
func checkYubiKey(reg core.Registry) KeyCheckResult {
	adapter, err := yubikey.NewYubiKeyAdapter(func() (string, error) { return "", nil })
	if err != nil {
		return KeyCheckResult{Error: fmt.Errorf("yubikey: %w", err)}
	}
	defer adapter.Close()

	pubKey, err := adapter.ExportPublicKey()
	if err != nil {
		return KeyCheckResult{Error: fmt.Errorf("yubikey: %w", err)}
	}

	hash := sha256.Sum256(pubKey[:])
	fp := hex.EncodeToString(hash[:])

	today := time.Now().UTC().Format("2006-01-02")
	entry := registry.FindMatchingEntryAt(reg, pubKey, today)

	return KeyCheckResult{
		Found:       entry != nil,
		Fingerprint: fp,
		Entry:       entry,
	}
}

// formatKeyResult converts a KeyCheckResult into a user-friendly status string
// and detail lines for display.
func formatKeyResult(result KeyCheckResult) (status string, details []string) {
	if result.Error != nil {
		switch core.ClassifyHardwareError(result.Error) {
		case core.HwErrSmartcard:
			status = "Smart card service not available"
		case core.HwErrHardware:
			status = "Please plug in your YubiKey and try again"
		default:
			status = "Failed to read YubiKey"
		}
		return status, nil
	}

	if result.Found && result.Entry != nil {
		status = "Key found in registry"
		details = []string{
			"Authority: " + result.Entry.Authority,
			"Valid from: " + core.FormatDateDisplay(result.Entry.From),
		}
		if result.Entry.To != nil {
			details = append(details, "Valid to: "+core.FormatDateDisplay(*result.Entry.To))
		} else {
			details = append(details, "Valid to: (no expiry)")
		}
		details = append(details, "Fingerprint: "+result.Fingerprint)
		if note := strings.TrimSpace(result.Entry.Note); note != "" {
			details = append(details, "Note: "+result.Entry.Note)
		}
		return status, details
	}

	status = "Key NOT found in registry"
	details = []string{"Fingerprint: " + result.Fingerprint}
	return status, details
}

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
		go func() {
			result := checkYubiKey(reg)
			fyne.Do(func() {
				checkBtn.Enable()
				status, details := formatKeyResult(result)
				statusLabel.SetText(status)
				for _, line := range details {
					resultArea.Add(widget.NewLabel(line))
				}
			})
		}()
	}

	if !online {
		checkBtn.Disable()
		statusLabel.SetText("Registry unavailable — connect to internet to check key")
	}

	topBar := container.NewBorder(nil, nil, nil, nil, container.NewBorder(nil, nil, checkBtn, nil, statusLabel))
	return container.NewBorder(topBar, nil, nil, nil, resultArea)
}
