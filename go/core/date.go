// Package core provides cryptographic primitives and utilities for the
// RHG Authenticator credential system.
package core

import "regexp"

// dateRE matches the YYYY-MM-DD format strictly.
var dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// daysInMonth gives the maximum day for each month (non-leap year).
var daysInMonth = [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// isLeapYear reports whether year is a leap year.
func isLeapYear(year int) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

// IsValidDate validates a YYYY-MM-DD date string with calendar-correct
// day checking. It rejects year 0000 and invalid day/month combinations
// (e.g., Feb 30, April 31). Leap years are handled correctly.
func IsValidDate(s string) bool {
	if !dateRE.MatchString(s) {
		return false
	}

	// Parse components. The regex guarantees exactly 4-2-2 digits with
	// hyphens, so Atoi cannot fail. We inline the parse to avoid
	// strconv import overhead.
	year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
	month := int(s[5]-'0')*10 + int(s[6]-'0')
	day := int(s[8]-'0')*10 + int(s[9]-'0')

	if year < 1 {
		return false
	}
	if month < 1 || month > 12 {
		return false
	}

	maxDay := daysInMonth[month-1]
	if month == 2 && isLeapYear(year) {
		maxDay = 29
	}

	return day >= 1 && day <= maxDay
}
