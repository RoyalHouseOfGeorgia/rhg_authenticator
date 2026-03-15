package gui

import (
	"regexp"
	"strings"
)

// Hardware error categories returned by classifyHardwareError.
const (
	hwErrSmartcard = "smartcard"
	hwErrPIN       = "pin"
	hwErrHardware  = "hardware"
)

// pinRE matches the word "pin" as a whole word (case-insensitive),
// avoiding false positives like "spinning", "hairpin", "pinot".
var pinRE = regexp.MustCompile(`(?i)\bpin\b`)

// scardRE matches "scard" as a whole word (case-insensitive),
// avoiding false positives like "discard".
var scardRE = regexp.MustCompile(`(?i)\bscard\b`)

// classifyHardwareError returns a category for hardware-related errors.
// Returns "" if the error doesn't match any known hardware pattern.
func classifyHardwareError(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "pcsc") || scardRE.MatchString(err.Error()):
		return hwErrSmartcard
	case pinRE.MatchString(err.Error()):
		return hwErrPIN
	case strings.Contains(lower, "yubikey") || strings.Contains(lower, "smart card"):
		return hwErrHardware
	default:
		return ""
	}
}
