package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// --- FilterRecords tests ---

func TestFilterRecords_EmptyQuery(t *testing.T) {
	records := []issuancelog.IssuanceRecord{
		{Recipient: "Alice", Date: "2026-01-01"},
		{Recipient: "Bob", Date: "2026-02-01"},
		{Recipient: "Charlie", Date: "2026-03-01"},
	}
	result := FilterRecords(records, "")
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
	records := []issuancelog.IssuanceRecord{
		{Recipient: "Alice Smith"},
		{Recipient: "Bob Jones"},
		{Recipient: "ALICE Johnson"},
	}
	result := FilterRecords(records, "alice")
	if len(result) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result))
	}
}

func TestFilterRecords_SubstringMatch(t *testing.T) {
	records := []issuancelog.IssuanceRecord{
		{Recipient: "Alexander the Great"},
		{Recipient: "Alexandra Smith"},
		{Recipient: "Bob Jones"},
	}
	result := FilterRecords(records, "alex")
	if len(result) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result))
	}
}

func TestFilterRecords_NoMatch(t *testing.T) {
	records := []issuancelog.IssuanceRecord{
		{Recipient: "Alice"},
		{Recipient: "Bob"},
	}
	result := FilterRecords(records, "Charlie")
	if len(result) != 0 {
		t.Fatalf("expected 0 records, got %d", len(result))
	}
}

func TestFilterRecords_WhitespaceQuery(t *testing.T) {
	records := []issuancelog.IssuanceRecord{
		{Recipient: "Alice"},
	}
	// Whitespace-only query should match all.
	result := FilterRecords(records, "   ")
	if len(result) != 1 {
		t.Fatalf("expected 1 record, got %d", len(result))
	}
}

func TestFilterRecords_EmptySlice(t *testing.T) {
	result := FilterRecords(nil, "")
	if len(result) != 0 {
		t.Fatalf("expected 0 records, got %d", len(result))
	}
}

func TestFilterRecords_ReverseOrder(t *testing.T) {
	records := []issuancelog.IssuanceRecord{
		{Recipient: "First", Date: "2026-01-01"},
		{Recipient: "Second", Date: "2026-06-01"},
		{Recipient: "Third", Date: "2026-12-01"},
	}
	result := FilterRecords(records, "")
	if result[0].Recipient != "Third" || result[1].Recipient != "Second" || result[2].Recipient != "First" {
		t.Errorf("records not in reverse order: %v", result)
	}
}

// --- formatRecordSummary tests ---

func TestFormatRecordSummary(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
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
	rec := issuancelog.IssuanceRecord{
		Date:      "2026-03-14",
		Recipient: "John Doe",
		Honor:     "Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ", // Very long title
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "...") {
		t.Error("long honor should be truncated with ellipsis")
	}
}

// --- FormatRecordDetail tests ---

func TestFormatRecordDetail(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Timestamp:       "2026-03-14T10:30:00Z",
		Recipient:       "John Doe",
		Honor:           "Test Honor",
		Detail:          "Test Detail",
		Date:            "2026-03-14",
		PayloadSHA256:   "abcdef1234567890",
		SignatureB64URL: "dummysig",
	}
	got := FormatRecordDetail(rec)

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

// --- FormatRecordSummaryWithRevocation tests ---

func TestFormatRecordSummaryWithRevocation_NotRevoked(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Order of the Crown of Georgia",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	revokedHashes := map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000000": true,
	}
	got := FormatRecordSummaryWithRevocation(rec, revokedHashes)
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
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Order of the Crown of Georgia",
		PayloadSHA256: hash,
	}
	revokedHashes := map[string]bool{
		hash: true,
	}
	got := FormatRecordSummaryWithRevocation(rec, revokedHashes)
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
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "Jane Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
	}
	revokedHashes := map[string]bool{
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789": true,
	}
	got := FormatRecordSummaryWithRevocation(rec, revokedHashes)
	if !strings.HasPrefix(got, "[REVOKED] ") {
		t.Errorf("case-insensitive match should still mark as revoked, got: %q", got)
	}
}

func TestFormatRecordSummaryWithRevocation_NilMap(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	got := FormatRecordSummaryWithRevocation(rec, nil)
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("nil map should not produce [REVOKED] prefix, got: %q", got)
	}
	want := formatRecordSummary(rec)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatRecordSummaryWithRevocation_EmptyMap(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	got := FormatRecordSummaryWithRevocation(rec, map[string]bool{})
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("empty map should not produce [REVOKED] prefix, got: %q", got)
	}
}

func TestFormatRecordSummaryWithRevocation_EmptyHash(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:          "2026-03-14",
		Recipient:     "John Doe",
		Honor:         "Test Honor",
		PayloadSHA256: "",
	}
	revokedHashes := map[string]bool{
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789": true,
	}
	got := FormatRecordSummaryWithRevocation(rec, revokedHashes)
	if strings.HasPrefix(got, "[REVOKED]") {
		t.Errorf("empty hash should not match revoked set, got: %q", got)
	}
}

// TestShouldEnableRevoke pins the Revoke-enable rule: enabled only when a usable
// client exists AND the revocation cache is ready AND a record is selected AND
// that record is not revoked. Covers the nil-safe form (selected == nil, the
// login-refresh case), the not-ready cache (failed/pending fetch), the nil
// revoked map (startup), and case-insensitive revocation lookup both directions
// (production stores keys lowercase).
func TestShouldEnableRevoke(t *testing.T) {
	rec := &issuancelog.IssuanceRecord{PayloadSHA256: "abc123"}
	recMixed := &issuancelog.IssuanceRecord{PayloadSHA256: "ABC123"} // same hash, mixed case

	tests := []struct {
		name       string
		clientNil  bool
		cacheReady bool
		selected   *issuancelog.IssuanceRecord
		revoked    map[string]bool
		want       bool
	}{
		{"no usable client", true, true, rec, map[string]bool{}, false},
		{"cache not ready (failed/pending fetch)", false, false, rec, map[string]bool{}, false},
		{"nil selection (no panic)", false, true, nil, map[string]bool{}, false},
		{"nil revoked map (startup)", false, true, rec, nil, true},
		{"selected and revoked", false, true, rec, map[string]bool{"abc123": true}, false},
		{"selected not revoked", false, true, rec, map[string]bool{}, true},
		{"mixed-case hash present in revoked", false, true, recMixed, map[string]bool{"abc123": true}, false},
		{"mixed-case hash absent from revoked", false, true, recMixed, map[string]bool{"other": true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldEnableRevoke(tt.clientNil, tt.cacheReady, tt.selected, tt.revoked); got != tt.want {
				t.Errorf("ShouldEnableRevoke(%v, %v, %+v, %v) = %v, want %v",
					tt.clientNil, tt.cacheReady, tt.selected, tt.revoked, got, tt.want)
			}
		})
	}
}

func TestHasRecords(t *testing.T) {
	tests := map[string]bool{
		"":                       false,
		" \n\t":                  false,
		"[]":                     false,
		"[\n  {},\n  {}\n]":      true,
		"not json":               true, // exported anyway for inspection
		`{"recipient":"object"}`: true,
	}
	for in, want := range tests {
		if got := HasRecords([]byte(in)); got != want {
			t.Errorf("HasRecords(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestRevokeFailureAction pins the revocation-PR error classification: only a
// 401 (directly or wrapped) restarts login; already-revoked and pending
// errors (directly or wrapped) are informational; every other error maps to
// ghapi.UserMessage and never echoes the raw error text into the dialog.
func TestRevokeFailureAction(t *testing.T) {
	const sessionExpired = "Your GitHub session expired. Please log in again."
	secret := "dial tcp internal.example:443: secret-detail"
	tests := []struct {
		name             string
		err              error
		wantUnauthorized bool
		wantInfoTitle    string
		wantMsg          string // checked only when non-empty
	}{
		{"401", &ghapi.APIError{StatusCode: 401, Message: "Bad credentials"}, true, "", sessionExpired},
		{"wrapped 401", fmt.Errorf("create branch: %w", &ghapi.APIError{StatusCode: 401}), true, "", sessionExpired},
		{"non-401", &ghapi.APIError{StatusCode: 500, Message: secret}, false, "", ""},
		{"already revoked", ghapi.ErrAlreadyRevoked, false, "Already Revoked", ghapi.UserMessage(ghapi.ErrAlreadyRevoked)},
		{"wrapped already revoked", fmt.Errorf("x: %w", ghapi.ErrAlreadyRevoked), false, "Already Revoked", ghapi.UserMessage(ghapi.ErrAlreadyRevoked)},
		{"pending", ghapi.ErrRevocationPending, false, "Revocation Pending", ghapi.UserMessage(ghapi.ErrRevocationPending)},
		{"wrapped pending", fmt.Errorf("x: %w", ghapi.ErrRevocationPending), false, "Revocation Pending", ghapi.UserMessage(ghapi.ErrRevocationPending)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unauthorized, infoTitle, msg := RevokeFailureAction(tc.err)
			if unauthorized != tc.wantUnauthorized {
				t.Errorf("unauthorized = %v, want %v", unauthorized, tc.wantUnauthorized)
			}
			if infoTitle != tc.wantInfoTitle {
				t.Errorf("infoTitle = %q, want %q", infoTitle, tc.wantInfoTitle)
			}
			if tc.wantMsg != "" && msg != tc.wantMsg {
				t.Errorf("msg = %q, want %q", msg, tc.wantMsg)
			}
			if strings.Contains(msg, "secret-detail") {
				t.Errorf("msg leaks raw error text: %q", msg)
			}
		})
	}
}
