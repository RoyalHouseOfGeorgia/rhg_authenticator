package service

import (
	"encoding/json"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// --- entryCellText tests ---

func TestEntryCellText_Column0_RowNumber(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        nil,
		Algorithm: "Ed25519",
		PublicKey: "dGVzdA==",
		Note:      "test note",
	}
	got := entryCellText(entry, 0, 0, "")
	if got != "1" {
		t.Errorf("col 0: got %q, want %q", got, "1")
	}
	// Also verify with a different index.
	got = entryCellText(entry, 0, 4, "")
	if got != "5" {
		t.Errorf("col 0 idx 4: got %q, want %q", got, "5")
	}
}

func TestEntryCellText_Column1_Authority(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 1, 0, "")
	if got != "Test Auth" {
		t.Errorf("col 1: got %q, want %q", got, "Test Auth")
	}
}

func TestEntryCellText_Column2_From(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 2, 0, "")
	want := core.FormatDateDisplay("2026-01-15")
	if got != want {
		t.Errorf("col 2: got %q, want %q", got, want)
	}
}

func TestEntryCellText_Column3_ToNil(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        nil,
		Note:      "test note",
	}
	got := entryCellText(entry, 3, 0, "")
	if got != "(none)" {
		t.Errorf("col 3 nil To: got %q, want %q", got, "(none)")
	}
}

func TestEntryCellText_Column3_ToNonNil(t *testing.T) {
	toDate := "2027-06-30"
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        &toDate,
		Note:      "test note",
	}
	got := entryCellText(entry, 3, 0, "")
	want := core.FormatDateDisplay("2027-06-30")
	if got != want {
		t.Errorf("col 3 non-nil To: got %q, want %q", got, want)
	}
}

func TestEntryCellText_Column4_Restrictions(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Extra:     map[string]json.RawMessage{"allowed_honors": json.RawMessage(`["Appointment"]`)},
	}
	got := entryCellText(entry, 4, 0, "")
	if got != "Appointment" {
		t.Errorf("col 4: got %q, want %q", got, "Appointment")
	}
}

func TestEntryCellText_Column5_Note(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 5, 0, "")
	if got != "test note" {
		t.Errorf("col 5: got %q, want %q", got, "test note")
	}
}

func TestEntryCellText_Column6_Fingerprint(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 6, 0, "SHA256:abc123")
	if got != "SHA256:abc123" {
		t.Errorf("col 6: got %q, want %q", got, "SHA256:abc123")
	}
}

func TestEntryCellText_Column6_InvalidKey(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 6, 0, "")
	if got != "(invalid key)" {
		t.Errorf("col 6 invalid key: got %q, want %q", got, "(invalid key)")
	}
}

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
		})
	}
}

// --- IsSafeGitHubURL tests ---

func TestIsSafeGitHubURL_GitHubHTTPS(t *testing.T) {
	_, ok := IsSafeGitHubURL("https://github.com/org/repo/pull/1")
	if !ok {
		t.Error("expected true for https://github.com URL")
	}
}

func TestIsSafeGitHubURL_GitHubSubdomain(t *testing.T) {
	_, ok := IsSafeGitHubURL("https://gist.github.com/user/123")
	if !ok {
		t.Error("expected true for https://gist.github.com URL")
	}
}

func TestIsSafeGitHubURL_NonGitHub(t *testing.T) {
	_, ok := IsSafeGitHubURL("https://evil.com/phishing")
	if ok {
		t.Error("expected false for non-GitHub host")
	}
}

func TestIsSafeGitHubURL_HTTP(t *testing.T) {
	_, ok := IsSafeGitHubURL("http://github.com/org/repo/pull/1")
	if ok {
		t.Error("expected false for http scheme")
	}
}

func TestIsSafeGitHubURL_Empty(t *testing.T) {
	_, ok := IsSafeGitHubURL("")
	if ok {
		t.Error("expected false for empty URL")
	}
}

func TestIsSafeGitHubURL_SuffixConfusion(t *testing.T) {
	_, ok := IsSafeGitHubURL("https://evil-github.com/fake")
	if ok {
		t.Error("expected false for evil-github.com (suffix confusion)")
	}
}
