package core

import "testing"

func TestFormatDateDisplay_Valid(t *testing.T) {
	got := FormatDateDisplay("2026-03-15")
	want := "2026-Mar-15"
	if got != want {
		t.Errorf("FormatDateDisplay(2026-03-15) = %q, want %q", got, want)
	}
}

func TestFormatDateDisplay_January(t *testing.T) {
	got := FormatDateDisplay("2026-01-01")
	want := "2026-Jan-01"
	if got != want {
		t.Errorf("FormatDateDisplay(2026-01-01) = %q, want %q", got, want)
	}
}

func TestFormatDateDisplay_Invalid(t *testing.T) {
	got := FormatDateDisplay("not-a-date")
	if got != "not-a-date" {
		t.Errorf("FormatDateDisplay(invalid) = %q, want original string", got)
	}
}

func TestFormatDateDisplay_Empty(t *testing.T) {
	got := FormatDateDisplay("")
	if got != "" {
		t.Errorf("FormatDateDisplay(\"\") = %q, want empty", got)
	}
}
