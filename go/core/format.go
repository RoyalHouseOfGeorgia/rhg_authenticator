package core

import "time"

// FormatDateDisplay converts a YYYY-MM-DD date string to YYYY-Mon-DD
// for unambiguous display (e.g., "2026-03-15" → "2026-Mar-15").
// If parsing fails, returns the input string unchanged.
func FormatDateDisplay(date string) string {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return date
	}
	return t.Format("2006-Jan-02")
}
