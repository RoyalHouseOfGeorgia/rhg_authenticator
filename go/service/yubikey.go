package service

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// checkYubiKey computes the fingerprint of pubKey, the inserted key's public
// key, and looks it up in the registry.
func checkYubiKey(reg core.Registry, pubKey [32]byte) KeyCheck {
	hash := sha256.Sum256(pubKey[:])
	today := time.Now().UTC().Format("2006-01-02")
	return keyCheck(registry.FindMatchingEntryAt(reg, pubKey, today), hex.EncodeToString(hash[:]))
}

// keyCheck is the KeyCheck shown for a key with SHA-256 fingerprint
// fingerprint and registry entry entry, nil when the key is not registered.
func keyCheck(entry *core.KeyEntry, fingerprint string) KeyCheck {
	if entry == nil {
		return KeyCheck{
			Outcome: KeyCheckNotFound,
			Status:  "Key NOT found in registry",
			Details: []string{"Fingerprint: " + fingerprint},
		}
	}
	details := []string{
		"Authority: " + entry.Authority,
		"Valid from: " + core.FormatDateDisplay(entry.From),
	}
	if entry.To != nil {
		details = append(details, "Valid to: "+core.FormatDateDisplay(*entry.To))
	} else {
		details = append(details, "Valid to: (no expiry)")
	}
	details = append(details, "Restrictions: "+restrictionsText(*entry), "Fingerprint: "+fingerprint)
	if note := strings.TrimSpace(entry.Note); note != "" {
		details = append(details, "Note: "+note)
	}
	return KeyCheck{Outcome: KeyCheckFound, Status: "Key found in registry", Details: details}
}

// keyReadFailure is the KeyCheck shown when the inserted key could not be read.
func keyReadFailure(err error) KeyCheck {
	var status string
	switch core.ClassifyHardwareError(err) {
	case core.HwErrTransient:
		status = core.MsgYubiKeyReset
	case core.HwErrSmartcard:
		status = "Smart card service not available"
	case core.HwErrHardware:
		status = "Please plug in your YubiKey and try again"
	default:
		// Reading the slot-9c key needs no PIN; an unexpected PIN prompt
		// fails with errNoPINForKeyRead (see noPIN) and lands here.
		status = "Failed to read YubiKey"
	}
	return KeyCheck{Outcome: KeyCheckFailed, Status: status}
}
