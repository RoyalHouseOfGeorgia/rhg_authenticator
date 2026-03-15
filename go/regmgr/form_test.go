package regmgr

import (
	"testing"
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

func TestBuildEntry_NoExpiry(t *testing.T) {
	entry := buildEntry("Auth", "2026-01-01", nil, "key123", "")
	if entry.To != nil {
		t.Errorf("To should be nil for no-expiry, got %v", entry.To)
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

func TestBuildEntry_PreservesKey(t *testing.T) {
	originalKey := "MCowBQYDK2VwAyEAoriginalkey="
	entry := buildEntry("Auth", "2026-01-01", nil, originalKey, "")
	if entry.PublicKey != originalKey {
		t.Errorf("PublicKey = %q, want %q", entry.PublicKey, originalKey)
	}
}

func TestBuildEntry_NormalizesAuthority(t *testing.T) {
	// U+00E9 (e-acute precomposed = NFC) vs U+0065 U+0301 (e + combining acute = NFD).
	nfd := "caf\u0065\u0301" // NFD form
	nfc := "caf\u00e9"       // NFC form

	// Verify our input is actually NFD (different from NFC form).
	if nfd == nfc {
		t.Skip("test input is already NFC, cannot test normalization")
	}

	entry := buildEntry(nfd, "2026-01-01", nil, "key", "")
	if entry.Authority != nfc {
		t.Errorf("Authority = %q, want NFC-normalized %q", entry.Authority, nfc)
	}
}

func TestBuildEntry_TrimsAuthority(t *testing.T) {
	entry := buildEntry("  Spaced Authority  ", "2026-01-01", nil, "key", "")
	if entry.Authority != "Spaced Authority" {
		t.Errorf("Authority = %q, want trimmed %q", entry.Authority, "Spaced Authority")
	}
}

func TestBuildEntry_AlgorithmAlwaysEd25519(t *testing.T) {
	// buildEntry should always set Algorithm to "Ed25519" regardless of input.
	entry := buildEntry("Auth", "2026-01-01", nil, "key", "note")
	if entry.Algorithm != "Ed25519" {
		t.Errorf("Algorithm = %q, want %q", entry.Algorithm, "Ed25519")
	}
}

func TestBuildEntry_EmptyNote(t *testing.T) {
	entry := buildEntry("Auth", "2026-01-01", nil, "key", "")
	if entry.Note != "" {
		t.Errorf("Note = %q, want empty string", entry.Note)
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

func TestBuildEntry_PreservesFromDate(t *testing.T) {
	entry := buildEntry("Auth", "2099-12-31", nil, "key", "")
	if entry.From != "2099-12-31" {
		t.Errorf("From = %q, want %q", entry.From, "2099-12-31")
	}
}
