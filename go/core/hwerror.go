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
)

// Patterns match error strings from piv-go and the PCSC daemon.
// Update if the piv-go library changes its error format.

// pinRE matches the word "pin" as a whole word (case-insensitive),
// avoiding false positives like "spinning", "hairpin", "pinot".
var pinRE = regexp.MustCompile(`(?i)\bpin\b`)

// scardRE matches "scard" as a whole word (case-insensitive),
// avoiding false positives like "discard".
var scardRE = regexp.MustCompile(`(?i)\bscard\b`)

// ClassifyHardwareError returns a category for hardware-related errors.
// Returns "" if the error doesn't match any known hardware pattern.
func ClassifyHardwareError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "pcsc") || scardRE.MatchString(err.Error()):
		return HwErrSmartcard
	case pinRE.MatchString(err.Error()):
		return HwErrPIN
	case strings.Contains(lower, "yubikey") || strings.Contains(lower, "smart card"):
		return HwErrHardware
	default:
		return ""
	}
}
