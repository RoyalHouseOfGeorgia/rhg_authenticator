package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestRestrictionsText(t *testing.T) {
	tests := []struct {
		name string
		raw  string // "" means allowed_honors absent from Extra
		want string
	}{
		{"absent", "", "(none)"},
		{"null", `null`, "(none)"},
		{"empty array", `[]`, "(none)"},
		{"all blank", `["", "  "]`, "(none)"},
		{"single honor", `["Appointment"]`, "Appointment"},
		{"blank items skipped", `["A", "", "B"]`, "A, B"},
		{"non-array string", `"Appointment"`, "(invalid)"},
		{"non-array object", `{"a": 1}`, "(invalid)"},
		{"malformed json", `[`, "(invalid)"},
		{"non-string item", `[1]`, "(invalid)"},
		{"null item", `["A", null]`, "(invalid)"},
		{"leading whitespace", `[" A"]`, "(invalid)"},
		{"trailing whitespace", `["A "]`, "(invalid)"},
		{"bidi control char", `["A\u202e"]`, "(invalid)"},
		{"C0 control char", `["A\u0001B"]`, "(invalid)"},
		{"tab only is control not blank", `["\t"]`, "(invalid)"},
		// U+FEFF: JS trim() strips it, so the verify page treats these as blank / untrimmed.
		{"BOM only is blank like JS trim", `["\ufeff"]`, "(none)"},
		{"trailing BOM is untrimmed like JS trim", `["Medal\ufeff"]`, "(invalid)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := core.KeyEntry{Authority: "Test Auth", From: "2026-01-15"}
			if tt.raw != "" {
				entry.Extra = map[string]json.RawMessage{"allowed_honors": json.RawMessage(tt.raw)}
			}
			if got := restrictionsText(entry); got != tt.want {
				t.Errorf("restrictionsText(%s) = %q, want %q", tt.raw, got, tt.want)
			}
			// allowedHonors is the parse behind the text.
			honors, valid := allowedHonors(entry)
			switch tt.want {
			case "(invalid)":
				if valid || honors != nil {
					t.Errorf("allowedHonors(%s) = %q, %v; want invalid", tt.raw, honors, valid)
				}
			case "(none)":
				if !valid || len(honors) != 0 {
					t.Errorf("allowedHonors(%s) = %q, %v; want unrestricted", tt.raw, honors, valid)
				}
			default:
				if !valid || strings.Join(honors, ", ") != tt.want {
					t.Errorf("allowedHonors(%s) = %q, %v; want %s", tt.raw, honors, valid, tt.want)
				}
			}
		})
	}
}
