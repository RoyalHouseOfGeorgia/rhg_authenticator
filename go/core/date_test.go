package core

import (
	"fmt"
	"testing"
)

func TestIsValidDate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid dates
		{"standard date", "2024-01-15", true},
		{"first day of year", "2024-01-01", true},
		{"last day of year", "2024-12-31", true},
		{"year 0001", "0001-01-01", true},
		{"year 9999", "9999-12-31", true},

		// Leap year Feb 29
		{"leap year div by 4", "2024-02-29", true},
		{"century leap year 2000", "2000-02-29", true},
		{"leap year 1600", "1600-02-29", true},

		// Non-leap year Feb 29
		{"non-leap year", "2023-02-29", false},
		{"century non-leap 1900", "1900-02-29", false},
		{"century non-leap 2100", "2100-02-29", false},

		// Month boundaries
		{"Jan 31", "2024-01-31", true},
		{"Feb 28 non-leap", "2023-02-28", true},
		{"Mar 31", "2024-03-31", true},
		{"Apr 30", "2024-04-30", true},
		{"May 31", "2024-05-31", true},
		{"Jun 30", "2024-06-30", true},
		{"Jul 31", "2024-07-31", true},
		{"Aug 31", "2024-08-31", true},
		{"Sep 30", "2024-09-30", true},
		{"Oct 31", "2024-10-31", true},
		{"Nov 30", "2024-11-30", true},
		{"Dec 31", "2024-12-31", true},

		// Invalid months
		{"month 0", "2024-00-15", false},
		{"month 13", "2024-13-15", false},

		// Invalid days
		{"day 0", "2024-01-00", false},
		{"Feb 30", "2024-02-30", false},
		{"Apr 31", "2024-04-31", false},
		{"Jun 31", "2024-06-31", false},
		{"Sep 31", "2024-09-31", false},
		{"Nov 31", "2024-11-31", false},
		{"Jan 32", "2024-01-32", false},

		// Year 0000
		{"year 0000", "0000-01-01", false},

		// Wrong format
		{"no dashes", "20240115", false},
		{"slash separator", "2024/01/15", false},
		{"too short", "24-01-15", false},
		{"trailing space", "2024-01-15 ", false},
		{"leading space", " 2024-01-15", false},
		{"extra digits", "12024-01-15", false},
		{"empty string", "", false},
		{"letters", "abcd-ef-gh", false},
		{"single digit month", "2024-1-15", false},
		{"single digit day", "2024-01-5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidDate(tt.input)
			if got != tt.want {
				t.Errorf("IsValidDate(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLeapYear(t *testing.T) {
	tests := []struct {
		year int
		want bool
	}{
		{2024, true},   // divisible by 4
		{2023, false},  // not divisible by 4
		{1900, false},  // divisible by 100 but not 400
		{2000, true},   // divisible by 400
		{1600, true},   // divisible by 400
		{2100, false},  // divisible by 100 but not 400
		{4, true},      // small leap year
		{1, false},     // year 1
		{400, true},    // divisible by 400
		{100, false},   // divisible by 100 but not 400
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("year_%d", tt.year), func(t *testing.T) {
			got := isLeapYear(tt.year)
			if got != tt.want {
				t.Errorf("isLeapYear(%d) = %v, want %v", tt.year, got, tt.want)
			}
		})
	}
}
