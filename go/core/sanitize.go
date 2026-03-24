package core

// MaxLogRunes is the maximum number of runes kept in sanitized log output.
const MaxLogRunes = 500

// SanitizeForLog replaces control characters (runes < 0x20) with spaces
// and truncates to MaxLogRunes runes to prevent log injection and unbounded
// log output from untrusted API responses or error messages.
func SanitizeForLog(s string) string {
	runes := []rune(s)
	if len(runes) > MaxLogRunes {
		runes = runes[:MaxLogRunes]
	}
	for i, r := range runes {
		if r < 0x20 {
			runes[i] = ' '
		}
	}
	return string(runes)
}
