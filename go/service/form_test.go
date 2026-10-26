package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func TestBuildEntry_Basic(t *testing.T) {
	entry := buildEntry("Test Authority", "2026-01-01", nil, "dGVzdGtleQ==", "a note")
	if entry.Authority != "Test Authority" {
		t.Errorf("Authority = %q, want %q", entry.Authority, "Test Authority")
	}
	if entry.From != "2026-01-01" {
		t.Errorf("From = %q, want %q", entry.From, "2026-01-01")
	}
	if entry.To != nil {
		t.Errorf("To = %v, want nil", entry.To)
	}
	if entry.Algorithm != "Ed25519" {
		t.Errorf("Algorithm = %q, want %q", entry.Algorithm, "Ed25519")
	}
	if entry.PublicKey != "dGVzdGtleQ==" {
		t.Errorf("PublicKey = %q, want %q", entry.PublicKey, "dGVzdGtleQ==")
	}
	if entry.Note != "a note" {
		t.Errorf("Note = %q, want %q", entry.Note, "a note")
	}
}

func TestBuildEntry_WithExpiry(t *testing.T) {
	to := "2027-12-31"
	entry := buildEntry("Auth", "2026-01-01", &to, "key123", "")
	if entry.To == nil {
		t.Fatal("To should not be nil when expiry is set")
	}
	if *entry.To != "2027-12-31" {
		t.Errorf("To = %q, want %q", *entry.To, "2027-12-31")
	}
}

func TestBuildEntry_TrimsAndNormalizesAuthority(t *testing.T) {
	// Combines trimming and NFC normalization.
	nfd := "  caf\u0065\u0301  "
	nfc := "caf\u00e9"

	entry := buildEntry(nfd, "2026-01-01", nil, "key", "")
	if entry.Authority != nfc {
		t.Errorf("Authority = %q, want trimmed+NFC %q", entry.Authority, nfc)
	}
}

func TestBuildEntry_PreservesNote(t *testing.T) {
	note := "Multi\nline\nnote with special chars: é"
	entry := buildEntry("Auth", "2026-01-01", nil, "key", note)
	if entry.Note != note {
		t.Errorf("Note = %q, want %q", entry.Note, note)
	}
}

func TestValidateEntryForm_Valid(t *testing.T) {
	err := validateEntryForm("Auth", "2026-01-01", "key", true, "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEntryForm_EmptyAuthority(t *testing.T) {
	err := validateEntryForm("", "2026-01-01", "key", true, "")
	if err == nil {
		t.Fatal("expected error for empty authority")
	}
}

func TestValidateEntryForm_WhitespaceAuthority(t *testing.T) {
	err := validateEntryForm("   ", "2026-01-01", "key", true, "")
	if err == nil {
		t.Fatal("expected error for whitespace authority")
	}
}

func TestValidateEntryForm_EmptyFrom(t *testing.T) {
	err := validateEntryForm("Auth", "", "key", true, "")
	if err == nil {
		t.Fatal("expected error for empty from date")
	}
}

func TestValidateEntryForm_InvalidFromDate(t *testing.T) {
	err := validateEntryForm("Auth", "not-a-date", "key", true, "")
	if err == nil {
		t.Fatal("expected error for invalid from date")
	}
}

func TestValidateEntryForm_InvalidToDate(t *testing.T) {
	err := validateEntryForm("Auth", "2026-01-01", "key", false, "not-a-date")
	if err == nil {
		t.Fatal("expected error for invalid to date")
	}
}

func TestValidateEntryForm_NoExpirySkipsToValidation(t *testing.T) {
	// When noExpiry is true, to date is ignored.
	err := validateEntryForm("Auth", "2026-01-01", "key", true, "garbage")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEntryForm_ToRequiredWhenNoExpiryUnchecked(t *testing.T) {
	err := validateEntryForm("Auth", "2026-01-01", "key", false, "")
	if err == nil {
		t.Fatal("expected error when noExpiry=false and to is empty")
	}
	if !strings.Contains(err.Error(), "To date is required") {
		t.Errorf("error = %v, want containing %q", err, "To date is required")
	}
}

func TestValidateEntryForm_ToBeforeFromAccepted(t *testing.T) {
	// from is informational: revoking a key registered with a future From
	// sets To to today, which is before From.
	if err := validateEntryForm("Auth", "2026-06-01", "key", false, "2025-01-01"); err != nil {
		t.Errorf("unexpected error when to < from: %v", err)
	}
}

func TestValidateEntryForm_ToEqualsFrom(t *testing.T) {
	err := validateEntryForm("Auth", "2026-01-01", "key", false, "2026-01-01")
	if err != nil {
		t.Errorf("unexpected error when to == from: %v", err)
	}
}

func TestValidateEntryForm_EmptyKey(t *testing.T) {
	err := validateEntryForm("Auth", "2026-01-01", "", true, "")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestImportKeyErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "reset error (wrapped verify pin chain)",
			err:  errors.New("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid"),
			want: core.MsgYubiKeyReset,
		},
		{
			name: "pcsc error",
			err:  errors.New("pcsc daemon not running"),
			want: "Smart card service not available.",
		},
		{
			name: "generic error",
			err:  errors.New("something else"),
			want: "No YubiKey detected — plug in and try again.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importKeyErrorMessage(tt.err); got != tt.want {
				t.Errorf("importKeyErrorMessage(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
