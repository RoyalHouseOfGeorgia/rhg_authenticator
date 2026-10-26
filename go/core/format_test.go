package core

import "testing"

func TestFormatDateDisplay(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"Valid", "2026-03-15", "2026-Mar-15"},
		{"January", "2026-01-01", "2026-Jan-01"},
		{"Invalid", "not-a-date", "not-a-date"},
		{"Empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatDateDisplay(tt.in); got != tt.want {
				t.Errorf("FormatDateDisplay(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
