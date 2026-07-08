package core

import (
	"regexp"
	"strings"
)

// Hardware error categories returned by ClassifyHardwareError.
const (
	HwErrSmartcard = "smartcard"
	HwErrPIN       = "pin"
	HwErrHardware  = "hardware"
	HwErrTransient = "transient" // PC/SC contention: card reset/removed/busy

	// MsgYubiKeyReset is the canonical user-facing message for HwErrTransient.
	MsgYubiKeyReset = "The YubiKey connection was reset. Another app (e.g. " +
		"Yubico Authenticator or a browser) may be using the key — close it and try again."
)

// Patterns match error strings from piv-go and the PCSC daemon.
// Update if the piv-go library changes its error format.

// pinRE matches the word "pin" as a whole word (case-insensitive),
// avoiding false positives like "spinning", "hairpin", "pinot".
var pinRE = regexp.MustCompile(`(?i)\bpin\b`)

// scardRE matches "scard" as a whole word (case-insensitive),
// avoiding false positives like "discard".
var scardRE = regexp.MustCompile(`(?i)\bscard\b`)

// transientCardPhrases are PC/SC contention errors (card reset/removed/unpowered/
// unresponsive, or a dropped transaction). The key is present but momentarily
// grabbed by another process — distinct from "not detected" (HwErrHardware).
// Each is a substring of the piv-go v2 winscard message (piv/pcsc_errors.go):
//
//	SCARD_W_RESET_CARD (0x80100068), SCARD_W_REMOVED_CARD (0x80100069),
//	SCARD_W_UNPOWERED_CARD (0x80100067), SCARD_W_UNRESPONSIVE_CARD (0x80100066),
//	SCARD_E_NOT_TRANSACTED (0x80100016).
//
// Entries MUST be lowercase — ClassifyHardwareError matches them against the
// lowercased error string. Anchored on "smart card has been reset" (not a bare
// "has been reset") so "PIN has been reset" stays HwErrPIN (see hwerror_test.go).
var transientCardPhrases = []string{
	"smart card has been reset",
	"smart card has been removed",
	"power has been removed from the smart card",
	"not responding to a reset",
	"non-existent transaction",
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ClassifyHardwareError returns a category for hardware-related errors.
// Returns "" if the error doesn't match any known hardware pattern.
func ClassifyHardwareError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case containsAny(lower, transientCardPhrases):
		return HwErrTransient
	case strings.Contains(lower, "pcsc") || scardRE.MatchString(lower):
		return HwErrSmartcard
	case pinRE.MatchString(lower):
		return HwErrPIN
	case strings.Contains(lower, "yubikey") || strings.Contains(lower, "smart card"):
		return HwErrHardware
	default:
		return ""
	}
}
