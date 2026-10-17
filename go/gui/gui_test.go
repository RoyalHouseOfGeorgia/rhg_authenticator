package gui

import (
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

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

// --- truncateRunes tests ---

func TestTruncateRunes_Short(t *testing.T) {
	got := truncateRunes("Short", 50)
	if got != "Short" {
		t.Errorf("truncateRunes = %q, want %q", got, "Short")
	}
}

func TestTruncateRunes_ExactLength(t *testing.T) {
	s := strings.Repeat("a", 50)
	got := truncateRunes(s, 50)
	if got != s {
		t.Errorf("truncateRunes exact = %q, want %q", got, s)
	}
}

func TestTruncateRunes_Long(t *testing.T) {
	s := strings.Repeat("a", 60)
	got := truncateRunes(s, 50)
	want := strings.Repeat("a", 50) + "..."
	if got != want {
		t.Errorf("truncateRunes long = %q, want %q", got, want)
	}
}

func TestTruncateRunes_Unicode(t *testing.T) {
	// Georgian characters are multi-byte but each is one rune.
	s := strings.Repeat("\u10D0", 55) // 55 Georgian "a" runes
	got := truncateRunes(s, 50)
	wantPrefix := strings.Repeat("\u10D0", 50) + "..."
	if got != wantPrefix {
		t.Errorf("truncateRunes unicode length mismatch")
	}
}

func TestTruncateRunes_Empty(t *testing.T) {
	got := truncateRunes("", 50)
	if got != "" {
		t.Errorf("truncateRunes empty = %q, want empty", got)
	}
}

func TestTruncateRunes_ZeroMax(t *testing.T) {
	got := truncateRunes("anything", 0)
	if got != "" {
		t.Errorf("truncateRunes zero max = %q, want empty", got)
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
	if !strings.Contains(got, "2026-Mar-14") {
		t.Error("summary should contain formatted date")
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
		Honor:     "Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ", // Very long title
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "...") {
		t.Error("long honor should be truncated with ellipsis")
	}
}

// --- formatRecordDetail tests ---

func TestFormatRecordDetail(t *testing.T) {
	rec := log.IssuanceRecord{
		Timestamp:       "2026-03-14T10:30:00Z",
		Recipient:       "John Doe",
		Honor:           "Test Honor",
		Detail:          "Test Detail",
		Date:            "2026-03-14",
		PayloadSHA256:   "abcdef1234567890",
		SignatureB64URL: "dummysig",
	}
	got := formatRecordDetail(rec)

	for _, field := range []string{
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail,
		rec.Date, rec.PayloadSHA256, rec.SignatureB64URL,
	} {
		if !strings.Contains(got, field) {
			t.Errorf("detail should contain %q", field)
		}
	}
}

// --- maxHonorDisplay constant test ---

func TestMaxHonorDisplay(t *testing.T) {
	if maxHonorDisplay != 50 {
		t.Errorf("maxHonorDisplay = %d, want 50", maxHonorDisplay)
	}
}

// --- formatRecordSummaryWithRevocation tests ---

func TestFormatRecordSummaryWithRevocation_NotRevoked(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Order of the Crown of Georgia",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	revokedHashes := map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000000": true,
	}
	got := formatRecordSummaryWithRevocation(rec, revokedHashes)
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("non-revoked record should not have [REVOKED] prefix, got: %q", got)
	}
	// Should match plain formatRecordSummary output.
	want := formatRecordSummary(rec)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatRecordSummaryWithRevocation_Revoked(t *testing.T) {
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Order of the Crown of Georgia",
		PayloadSHA256: hash,
	}
	revokedHashes := map[string]bool{
		hash: true,
	}
	got := formatRecordSummaryWithRevocation(rec, revokedHashes)
	if !strings.HasPrefix(got, "[REVOKED] ") {
		t.Errorf("revoked record should have [REVOKED] prefix, got: %q", got)
	}
	// The rest should be the normal summary.
	withoutPrefix := strings.TrimPrefix(got, "[REVOKED] ")
	want := formatRecordSummary(rec)
	if withoutPrefix != want {
		t.Errorf("after removing prefix: got %q, want %q", withoutPrefix, want)
	}
}

func TestFormatRecordSummaryWithRevocation_CaseInsensitive(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "Jane Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
	}
	revokedHashes := map[string]bool{
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789": true,
	}
	got := formatRecordSummaryWithRevocation(rec, revokedHashes)
	if !strings.HasPrefix(got, "[REVOKED] ") {
		t.Errorf("case-insensitive match should still mark as revoked, got: %q", got)
	}
}

func TestFormatRecordSummaryWithRevocation_NilMap(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	got := formatRecordSummaryWithRevocation(rec, nil)
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("nil map should not produce [REVOKED] prefix, got: %q", got)
	}
	want := formatRecordSummary(rec)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatRecordSummaryWithRevocation_EmptyMap(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	got := formatRecordSummaryWithRevocation(rec, map[string]bool{})
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("empty map should not produce [REVOKED] prefix, got: %q", got)
	}
}

func TestFormatRecordSummaryWithRevocation_EmptyHash(t *testing.T) {
	rec := log.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "",
	}
	revokedHashes := map[string]bool{
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789": true,
	}
	got := formatRecordSummaryWithRevocation(rec, revokedHashes)
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("empty hash should not match revoked set, got: %q", got)
	}
}
