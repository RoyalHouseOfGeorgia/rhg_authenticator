package core

import (
	"strings"
	"unicode"
)

// TrimJS trims a superset of what JavaScript's String.prototype.trim strips:
// Go's Unicode whitespace plus U+FEFF (which strings.TrimSpace keeps). It also
// strips U+0085, which JS keeps, but the control-character check rejects that
// anyway. Use wherever Go output must be accepted by the verify page (src/*.ts).
func TrimJS(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' })
}

// MaxLogRunes is the maximum number of runes kept in sanitized log output.
const MaxLogRunes = 500

// StripControlChars replaces control characters (C0, DEL, C1) and Unicode bidi
// overrides/isolates with spaces. Unlike SanitizeForLog, it does not truncate.
func StripControlChars(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if isControlOrBidi(r) {
			runes[i] = ' '
		}
	}
	return string(runes)
}

// SanitizeForLog replaces control characters (C0, DEL, C1) and Unicode bidi
// overrides/isolates with spaces, and truncates to MaxLogRunes runes.
// Prevents log injection and unbounded log output from untrusted sources.
func SanitizeForLog(s string) string {
	runes := []rune(s)
	if len(runes) > MaxLogRunes {
		runes = runes[:MaxLogRunes]
	}
	for i, r := range runes {
		if isControlOrBidi(r) {
			runes[i] = ' '
		}
	}
	return string(runes)
}

// isControlOrBidi reports whether r is a C0 control, DEL, C1 control, or
// Unicode bidi override/isolate/mark character. Matches the same set as
// controlCharPattern in credential.go and CONTROL_CHAR_PATTERN in
// src/credential.ts (the verify page); keep all three in sync.
func isControlOrBidi(r rune) bool {
	if r <= 0x1f || r == 0x7f {
		return true // C0 + DEL
	}
	if r >= 0x80 && r <= 0x9f {
		return true // C1
	}
	switch r {
	case 0x061c, 0x200e, 0x200f: // bidi marks
		return true
	}
	if r >= 0x202a && r <= 0x202e {
		return true // bidi overrides
	}
	if r >= 0x2066 && r <= 0x2069 {
		return true // bidi isolates
	}
	return false
}
