package gui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// --- formatKeyResult tests ---

func TestFormatKeyResult_Found(t *testing.T) {
	to := "2027-12-31"
	entry := &core.KeyEntry{
		Authority: "HRH Prince Davit",
		From:      "2026-01-01",
		To:        &to,
		Note:      "",
	}
	result := KeyCheckResult{
		Found:       true,
		Fingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Entry:       entry,
	}
	status, details := formatKeyResult(result)
	if status != "Key found in registry" {
		t.Errorf("status = %q, want %q", status, "Key found in registry")
	}
	if len(details) < 4 {
		t.Fatalf("expected at least 4 detail lines, got %d", len(details))
	}
	if !strings.Contains(details[0], "HRH Prince Davit") {
		t.Errorf("details[0] should contain authority, got: %q", details[0])
	}
	if !strings.HasPrefix(details[0], "Authority: ") {
		t.Errorf("details[0] should start with 'Authority: ', got: %q", details[0])
	}
	if !strings.Contains(details[1], "2026-Jan-01") {
		t.Errorf("details[1] should contain formatted from date, got: %q", details[1])
	}
	if !strings.Contains(details[2], "2027-Dec-31") {
		t.Errorf("details[2] should contain formatted to date, got: %q", details[2])
	}
	if !strings.Contains(details[3], "Fingerprint: ") {
		t.Errorf("details[3] should contain fingerprint, got: %q", details[3])
	}
}

func TestFormatKeyResult_NotFound(t *testing.T) {
	result := KeyCheckResult{
		Found:       false,
		Fingerprint: "deadbeef" + strings.Repeat("00", 28),
	}
	status, details := formatKeyResult(result)
	if status != "Key NOT found in registry" {
		t.Errorf("status = %q, want %q", status, "Key NOT found in registry")
	}
	if len(details) != 1 {
		t.Fatalf("expected 1 detail line, got %d", len(details))
	}
	if !strings.HasPrefix(details[0], "Fingerprint: ") {
		t.Errorf("details[0] should start with 'Fingerprint: ', got: %q", details[0])
	}
}

func TestFormatKeyResult_Error_PCSC(t *testing.T) {
	result := KeyCheckResult{Error: fmt.Errorf("yubikey: pcsc daemon not running")}
	status, details := formatKeyResult(result)
	if !strings.Contains(status, "Smart card service") {
		t.Errorf("status should mention smart card service, got: %q", status)
	}
	if details != nil {
		t.Errorf("details should be nil on error, got: %v", details)
	}
}

func TestFormatKeyResult_Error_NoYubiKey(t *testing.T) {
	result := KeyCheckResult{Error: fmt.Errorf("yubikey: no YubiKey detected")}
	status, details := formatKeyResult(result)
	if !strings.Contains(status, "plug in") {
		t.Errorf("status should mention 'plug in', got: %q", status)
	}
	if details != nil {
		t.Errorf("details should be nil on error, got: %v", details)
	}
}

func TestFormatKeyResult_NoExpiry(t *testing.T) {
	entry := &core.KeyEntry{
		Authority: "Test Authority",
		From:      "2026-01-01",
		To:        nil,
		Note:      "",
	}
	result := KeyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("aa", 32),
		Entry:       entry,
	}
	status, details := formatKeyResult(result)
	if status != "Key found in registry" {
		t.Errorf("status = %q, want %q", status, "Key found in registry")
	}
	foundNoExpiry := false
	for _, d := range details {
		if strings.Contains(d, "(no expiry)") {
			foundNoExpiry = true
		}
	}
	if !foundNoExpiry {
		t.Errorf("expected '(no expiry)' in details, got: %v", details)
	}
}

func TestFormatKeyResult_WithNote(t *testing.T) {
	to := "2027-12-31"
	entry := &core.KeyEntry{
		Authority: "Test Authority",
		From:      "2026-01-01",
		To:        &to,
		Note:      "Backup key for ceremonies",
	}
	result := KeyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("bb", 32),
		Entry:       entry,
	}
	_, details := formatKeyResult(result)
	foundNote := false
	for _, d := range details {
		if strings.HasPrefix(d, "Note: ") {
			foundNote = true
			if !strings.Contains(d, "Backup key for ceremonies") {
				t.Errorf("note detail should contain note text, got: %q", d)
			}
		}
	}
	if !foundNote {
		t.Errorf("expected note line in details, got: %v", details)
	}
}

func TestFormatKeyResult_EmptyNote(t *testing.T) {
	to := "2027-12-31"
	entry := &core.KeyEntry{
		Authority: "Test Authority",
		From:      "2026-01-01",
		To:        &to,
		Note:      "   ",
	}
	result := KeyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("cc", 32),
		Entry:       entry,
	}
	_, details := formatKeyResult(result)
	for _, d := range details {
		if strings.HasPrefix(d, "Note: ") {
			t.Errorf("whitespace-only note should be omitted, but found: %q", d)
		}
	}
}

