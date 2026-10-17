package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// keyCheckResult holds the result of a YubiKey registry check.
type keyCheckResult struct {
	Found       bool
	Fingerprint string         // SHA-256 hex of raw 32-byte public key
	Entry       *core.KeyEntry // non-nil if Found
	Error       error          // non-nil if check failed
}

// checkYubiKey computes the fingerprint of pubKey, the inserted key's public
// key, and searches the registry for a matching entry.
func checkYubiKey(reg core.Registry, pubKey [32]byte) keyCheckResult {

	hash := sha256.Sum256(pubKey[:])
	fp := hex.EncodeToString(hash[:])

	today := time.Now().UTC().Format("2006-01-02")
	entry := registry.FindMatchingEntryAt(reg, pubKey, today)

	return keyCheckResult{
		Found:       entry != nil,
		Fingerprint: fp,
		Entry:       entry,
	}
}

// formatKeyResult converts a keyCheckResult into a user-friendly status string
// and detail lines for display.
func formatKeyResult(result keyCheckResult) (status string, details []string) {
	if result.Error != nil {
		switch core.ClassifyHardwareError(result.Error) {
		case core.HwErrTransient:
			status = core.MsgYubiKeyReset
		case core.HwErrSmartcard:
			status = "Smart card service not available"
		case core.HwErrHardware:
			status = "Please plug in your YubiKey and try again"
		default:
			// HwErrPIN cannot occur here: the key check reads the slot-9c public
			// key/cert, which requires no PIN (readPin is a no-op).
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
