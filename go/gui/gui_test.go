package gui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// --- validateSignForm tests ---

func TestValidateSignForm_AllValid(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "For service", "2026-03-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSignForm_EmptyRecipient(t *testing.T) {
	err := validateSignForm("", honorTitles[0], "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty recipient")
	}
	if !strings.Contains(err.Error(), "Recipient") {
		t.Errorf("error should mention Recipient, got: %v", err)
	}
}

func TestValidateSignForm_WhitespaceOnlyRecipient(t *testing.T) {
	err := validateSignForm("   ", honorTitles[0], "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for whitespace-only recipient")
	}
}

func TestValidateSignForm_NoHonorSelected(t *testing.T) {
	err := validateSignForm("John Doe", "", "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty honor")
	}
	if !strings.Contains(err.Error(), "Honor") {
		t.Errorf("error should mention Honor, got: %v", err)
	}
}

func TestValidateSignForm_EmptyDetail(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty detail")
	}
	if !strings.Contains(err.Error(), "Detail") {
		t.Errorf("error should mention Detail, got: %v", err)
	}
}

func TestValidateSignForm_WhitespaceOnlyDetail(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "  \t ", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for whitespace-only detail")
	}
}

func TestValidateSignForm_InvalidDate_BadFormat(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "not-a-date")
	if err == nil {
		t.Fatal("expected error for invalid date")
	}
	if !strings.Contains(err.Error(), "Date") {
		t.Errorf("error should mention Date, got: %v", err)
	}
}

func TestValidateSignForm_InvalidDate_Feb30(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "2026-02-30")
	if err == nil {
		t.Fatal("expected error for Feb 30")
	}
}

func TestValidateSignForm_InvalidDate_Empty(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "")
	if err == nil {
		t.Fatal("expected error for empty date")
	}
}

func TestValidateSignForm_ValidLeapYear(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "2024-02-29")
	if err != nil {
		t.Fatalf("unexpected error for valid leap year date: %v", err)
	}
}

// --- buildFilename tests ---

func TestBuildFilename_SVG(t *testing.T) {
	got := buildFilename("2026-03-14", "abcd1234", "svg")
	want := "rhg-credential-2026-03-14-abcd1234-min3cm.svg"
	if got != want {
		t.Errorf("buildFilename SVG = %q, want %q", got, want)
	}
}

func TestBuildFilename_PNG(t *testing.T) {
	got := buildFilename("2026-03-14", "abcd1234", "png")
	want := "rhg-credential-2026-03-14-abcd1234-2048px.png"
	if got != want {
		t.Errorf("buildFilename PNG = %q, want %q", got, want)
	}
}

func TestBuildFilename_OtherExt(t *testing.T) {
	// Non-png extensions should use "min3cm" suffix.
	got := buildFilename("2026-01-01", "deadbeef", "pdf")
	want := "rhg-credential-2026-01-01-deadbeef-min3cm.pdf"
	if got != want {
		t.Errorf("buildFilename other = %q, want %q", got, want)
	}
}

// --- computeHash8 tests ---

func TestComputeHash8_ValidPayload(t *testing.T) {
	// Create a known payload via core.Encode.
	payload := []byte(`{"test":"data"}`)
	b64 := core.Encode(payload)

	hash8, err := computeHash8(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash8) != 8 {
		t.Fatalf("hash8 length = %d, want 8", len(hash8))
	}

	// Verify it matches the expected SHA-256 prefix.
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])[:8]
	if hash8 != want {
		t.Errorf("computeHash8 = %q, want %q", hash8, want)
	}
}

func TestComputeHash8_InvalidBase64(t *testing.T) {
	_, err := computeHash8("!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// --- filterRecords tests ---

func TestFilterRecords_EmptyQuery(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "Alice", Date: "2026-01-01"},
		{Recipient: "Bob", Date: "2026-02-01"},
		{Recipient: "Charlie", Date: "2026-03-01"},
	}
	result := filterRecords(records, "")
	if len(result) != 3 {
		t.Fatalf("expected 3 records, got %d", len(result))
	}
	// Should be in reverse order (newest first).
	if result[0].Recipient != "Charlie" {
		t.Errorf("first record = %q, want Charlie", result[0].Recipient)
	}
	if result[2].Recipient != "Alice" {
		t.Errorf("last record = %q, want Alice", result[2].Recipient)
	}
}

func TestFilterRecords_CaseInsensitive(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "Alice Smith"},
		{Recipient: "Bob Jones"},
		{Recipient: "ALICE Johnson"},
	}
	result := filterRecords(records, "alice")
	if len(result) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result))
	}
}

func TestFilterRecords_SubstringMatch(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "Alexander the Great"},
		{Recipient: "Alexandra Smith"},
		{Recipient: "Bob Jones"},
	}
	result := filterRecords(records, "alex")
	if len(result) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result))
	}
}

func TestFilterRecords_NoMatch(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "Alice"},
		{Recipient: "Bob"},
	}
	result := filterRecords(records, "Charlie")
	if len(result) != 0 {
		t.Fatalf("expected 0 records, got %d", len(result))
	}
}

func TestFilterRecords_WhitespaceQuery(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "Alice"},
	}
	// Whitespace-only query should match all.
	result := filterRecords(records, "   ")
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
}

func TestFilterRecords_EmptySlice(t *testing.T) {
	result := filterRecords(nil, "")
	if len(result) != 0 {
		t.Fatalf("expected 0 records, got %d", len(result))
	}
}

func TestFilterRecords_ReverseOrder(t *testing.T) {
	records := []log.IssuanceRecord{
		{Recipient: "First", Date: "2026-01-01"},
		{Recipient: "Second", Date: "2026-06-01"},
		{Recipient: "Third", Date: "2026-12-01"},
	}
	result := filterRecords(records, "")
	if result[0].Recipient != "Third" || result[1].Recipient != "Second" || result[2].Recipient != "First" {
		t.Errorf("records not in reverse order: %v", result)
	}
}

// --- truncateHonor tests ---

func TestTruncateHonor_Short(t *testing.T) {
	got := truncateHonor("Short", 50)
	if got != "Short" {
		t.Errorf("truncateHonor = %q, want %q", got, "Short")
	}
}

func TestTruncateHonor_ExactLength(t *testing.T) {
	s := strings.Repeat("a", 50)
	got := truncateHonor(s, 50)
	if got != s {
		t.Errorf("truncateHonor exact = %q, want %q", got, s)
	}
}

func TestTruncateHonor_Long(t *testing.T) {
	s := strings.Repeat("a", 60)
	got := truncateHonor(s, 50)
	want := strings.Repeat("a", 50) + "..."
	if got != want {
		t.Errorf("truncateHonor long = %q, want %q", got, want)
	}
}

func TestTruncateHonor_Unicode(t *testing.T) {
	// Georgian characters are multi-byte but each is one rune.
	s := strings.Repeat("\u10D0", 55) // 55 Georgian "a" runes
	got := truncateHonor(s, 50)
	wantPrefix := strings.Repeat("\u10D0", 50) + "..."
	if got != wantPrefix {
		t.Errorf("truncateHonor unicode length mismatch")
	}
}

func TestTruncateHonor_Empty(t *testing.T) {
	got := truncateHonor("", 50)
	if got != "" {
		t.Errorf("truncateHonor empty = %q, want empty", got)
	}
}

// --- formatRecordSummary tests ---

func TestFormatRecordSummary(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:      "2026-03-14",
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "2026-03-14") {
		t.Error("summary should contain date")
	}
	if !strings.Contains(got, "John Doe") {
		t.Error("summary should contain recipient")
	}
	if !strings.Contains(got, "Order of the Crown") {
		t.Error("summary should contain honor")
	}
}

func TestFormatRecordSummary_LongHonor(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:      "2026-03-14",
		Recipient: "John Doe",
		Honor:     honorTitles[0], // Very long title
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "...") {
		t.Error("long honor should be truncated with ellipsis")
	}
}

// --- formatRecordDetail tests ---

func TestFormatRecordDetail(t *testing.T) {
	rec := log.IssuanceRecord{
		Timestamp:     "2026-03-14T10:30:00Z",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		Detail:        "Test Detail",
		Date:          "2026-03-14",
		Authority:     "Test Authority",
		PayloadSHA256: "abcdef1234567890",
		SignatureB64URL:  "dummysig",
	}
	got := formatRecordDetail(rec)

	for _, field := range []string{
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail,
		rec.Date, rec.Authority, rec.PayloadSHA256, rec.SignatureB64URL,
	} {
		if !strings.Contains(got, field) {
			t.Errorf("detail should contain %q", field)
		}
	}
}

// --- honorTitles constant tests ---

func TestHonorTitles_Count(t *testing.T) {
	if len(honorTitles) != 5 {
		t.Errorf("honorTitles count = %d, want 5", len(honorTitles))
	}
}

func TestHonorTitles_NotEmpty(t *testing.T) {
	for i, title := range honorTitles {
		if strings.TrimSpace(title) == "" {
			t.Errorf("honorTitles[%d] is empty", i)
		}
	}
}

func TestHonorTitles_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, title := range honorTitles {
		if seen[title] {
			t.Errorf("duplicate honor title: %q", title)
		}
		seen[title] = true
	}
}

func TestHonorTitles_Contains_Eagle(t *testing.T) {
	found := false
	for _, title := range honorTitles {
		if strings.Contains(title, "Eagle") {
			found = true
			break
		}
	}
	if !found {
		t.Error("honorTitles should contain the Eagle order")
	}
}

func TestHonorTitles_Contains_Ennoblement(t *testing.T) {
	found := false
	for _, title := range honorTitles {
		if title == "Ennoblement" {
			found = true
			break
		}
	}
	if !found {
		t.Error("honorTitles should contain Ennoblement")
	}
}

// --- maxHonorDisplay constant test ---

func TestMaxHonorDisplay(t *testing.T) {
	if maxHonorDisplay != 50 {
		t.Errorf("maxHonorDisplay = %d, want 50", maxHonorDisplay)
	}
}

// --- friendlyYubiKeyError tests ---

func TestFriendlyYubiKeyError_YubiKeyError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("no YubiKey detected"))
	if !strings.Contains(got, "plug in") {
		t.Errorf("expected 'plug in' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_CardError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("smart card not found"))
	if !strings.Contains(got, "plug in") {
		t.Errorf("expected 'plug in' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_PCSCError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("pcsc daemon not running"))
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_SCARDError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("scard: service not available"))
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_GenericError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("unexpected failure"))
	if !strings.Contains(got, "Failed to connect") {
		t.Errorf("expected 'Failed to connect' message, got: %q", got)
	}
	if !strings.Contains(got, "unexpected failure") {
		t.Errorf("expected error details in message, got: %q", got)
	}
}
