package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	result := keyCheckResult{
		Found:       true,
		Fingerprint: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Entry:       entry,
	}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckFound {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckFound)
	}
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
	if details[3] != "Restrictions: (none)" {
		t.Errorf("details[3] = %q, want the key's honor restrictions", details[3])
	}
	if !strings.Contains(details[4], "Fingerprint: ") {
		t.Errorf("details[4] should contain fingerprint, got: %q", details[4])
	}
}

// TestFormatKeyResult_Restricted: a key limited to some honors lists them, so
// a check that says "found" explains a later honor refusal.
func TestFormatKeyResult_Restricted(t *testing.T) {
	entry := &core.KeyEntry{Authority: "A", From: "2026-01-01",
		Extra: map[string]json.RawMessage{"allowed_honors": json.RawMessage(`["Appointment"]`)}}
	kc := formatKeyResult(keyCheckResult{Found: true, Fingerprint: "ab", Entry: entry})
	if !slices.Contains(kc.Details, "Restrictions: Appointment") {
		t.Errorf("details = %q, want the allowed honors", kc.Details)
	}
}

func TestFormatKeyResult_NotFound(t *testing.T) {
	result := keyCheckResult{
		Found:       false,
		Fingerprint: "deadbeef" + strings.Repeat("00", 28),
	}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckNotFound {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckNotFound)
	}
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
	result := keyCheckResult{Error: fmt.Errorf("yubikey: pcsc daemon not running")}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckFailed {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckFailed)
	}
	if !strings.Contains(status, "Smart card service") {
		t.Errorf("status should mention smart card service, got: %q", status)
	}
	if details != nil {
		t.Errorf("details should be nil on error, got: %v", details)
	}
}

func TestFormatKeyResult_Error_NoYubiKey(t *testing.T) {
	result := keyCheckResult{Error: fmt.Errorf("yubikey: no YubiKey detected")}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckFailed {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckFailed)
	}
	if !strings.Contains(status, "plug in") {
		t.Errorf("status should mention 'plug in', got: %q", status)
	}
	if details != nil {
		t.Errorf("details should be nil on error, got: %v", details)
	}
}

func TestFormatKeyResult_Error_Transient(t *testing.T) {
	// A card reset must surface the canonical reset message, even though
	// "verify pin" appears in the wrapped error chain.
	result := keyCheckResult{Error: errors.New("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid")}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckFailed {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckFailed)
	}
	if status != core.MsgYubiKeyReset {
		t.Errorf("status = %q, want %q", status, core.MsgYubiKeyReset)
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
	result := keyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("aa", 32),
		Entry:       entry,
	}
	kc := formatKeyResult(result)
	outcome, status, details := kc.Outcome, kc.Status, kc.Details
	if outcome != KeyCheckFound {
		t.Errorf("outcome = %q, want %q", outcome, KeyCheckFound)
	}
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
	result := keyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("bb", 32),
		Entry:       entry,
	}
	details := formatKeyResult(result).Details
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
	result := keyCheckResult{
		Found:       true,
		Fingerprint: strings.Repeat("cc", 32),
		Entry:       entry,
	}
	details := formatKeyResult(result).Details
	for _, d := range details {
		if strings.HasPrefix(d, "Note: ") {
			t.Errorf("whitespace-only note should be omitted, but found: %q", d)
		}
	}
}
