package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if !strings.Contains(err.Error(), "recipient") {
		t.Errorf("error should mention recipient, got: %v", err)
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
	if !strings.Contains(err.Error(), "honor") {
		t.Errorf("error should mention honor, got: %v", err)
	}
}

func TestValidateSignForm_EmptyDetail(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty detail")
	}
	if !strings.Contains(err.Error(), "detail") {
		t.Errorf("error should mention detail, got: %v", err)
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
	if !strings.Contains(err.Error(), "date") {
		t.Errorf("error should mention date, got: %v", err)
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

// --- sanitizeError tests ---

func TestSanitizeError_PCSC(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("pcsc daemon not running"))
	if got != "test: smart card service error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_SCARD(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("scard: service unavailable"))
	if got != "test: smart card service error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_PIN(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("wrong PIN entered"))
	if got != "test: PIN error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_YubiKey(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("no YubiKey detected"))
	if got != "test: hardware device error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_Card(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("smart card not found"))
	if got != "test: hardware device error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_CardNoFalsePositive(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("discard data"))
	if got != "test: unexpected error" {
		t.Errorf("got %q, want %q", got, "test: unexpected error")
	}
}

func TestSanitizeError_Generic(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("unexpected failure"))
	if got != "test: unexpected error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_Nil(t *testing.T) {
	got := sanitizeError("test", nil)
	if got != "test: unknown error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_EmptyMessage(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf(""))
	if got != "test: unexpected error" {
		t.Errorf("got %q, want %q", got, "test: unexpected error")
	}
}

// --- friendlyYubiKeyError tests ---

func TestFriendlyYubiKeyError_Nil(t *testing.T) {
	got := friendlyYubiKeyError(nil, nil)
	if got != "Unknown YubiKey error" {
		t.Errorf("got %q, want %q", got, "Unknown YubiKey error")
	}
}

func TestFriendlyYubiKeyError_YubiKeyError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("no YubiKey detected"), nil)
	if !strings.Contains(got, "plug in") {
		t.Errorf("expected 'plug in' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_CardError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("smart card not found"), nil)
	if !strings.Contains(got, "plug in") {
		t.Errorf("expected 'plug in' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_PCSCError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("pcsc daemon not running"), nil)
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_SCARDError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("scard: service not available"), nil)
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_GenericError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	got := friendlyYubiKeyError(fmt.Errorf("unexpected failure"), logger)
	if !strings.Contains(got, "Failed to connect") {
		t.Errorf("expected 'Failed to connect' message, got: %q", got)
	}
	if !strings.Contains(got, "debug.log") {
		t.Errorf("expected debug.log reference in message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_GenericError_RawLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "debug.log")
	logger := &debugLogger{path: logPath}

	friendlyYubiKeyError(fmt.Errorf("unexpected failure"), logger)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("debug log file not created: %v", err)
	}
	content := string(data)
	// The debug log must contain the RAW error string, not sanitized to "unexpected error".
	if !strings.Contains(content, "unexpected failure") {
		t.Errorf("debug log should contain raw error 'unexpected failure', got: %q", content)
	}
	if strings.Contains(content, "unexpected error") {
		t.Errorf("debug log should NOT contain sanitized 'unexpected error', got: %q", content)
	}
}

// --- debugLogger tests ---

func TestDebugLogger_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	logger.log("test message")

	data, err := os.ReadFile(logger.path)
	if err != nil {
		t.Fatalf("debug log file not created: %v", err)
	}
	if !strings.Contains(string(data), "test message") {
		t.Errorf("debug log missing message, got: %q", string(data))
	}
}

func TestDebugLogger_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	logger.log("perm check")

	info, err := os.Stat(logger.path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestDebugLogger_AppendMode(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}

	logger.log("first message")
	logger.log("second message")

	data, err := os.ReadFile(logger.path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "first message") {
		t.Errorf("missing first message, got: %q", content)
	}
	if !strings.Contains(content, "second message") {
		t.Errorf("missing second message, got: %q", content)
	}
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestDebugLogger_EmptyPath(t *testing.T) {
	logger := &debugLogger{path: ""}
	// Should not panic or create any file.
	logger.log("should be a no-op")
}

func TestDebugLogger_NilLogger(t *testing.T) {
	var logger *debugLogger
	// Should not panic.
	logger.log("should not panic")
}

func TestDebugLogger_TimestampFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	logger.log("ts check")

	data, err := os.ReadFile(logger.path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	content := string(data)
	// RFC3339 timestamps contain a "T" between date and time.
	if !strings.Contains(content, "T") || !strings.Contains(content, "Z") {
		t.Errorf("expected RFC3339 timestamp, got: %q", content)
	}
	// Line should be bracketed: [timestamp] message
	if !strings.HasPrefix(content, "[") {
		t.Errorf("expected line to start with '[', got: %q", content)
	}
}

// --- signFlowErrorMessage tests ---

func TestSignFlowErrorMessage_ExportPublicKey(t *testing.T) {
	got := signFlowErrorMessage(fmt.Errorf("export public key: hardware failure"), nil)
	if !strings.Contains(got, "Failed to read YubiKey") {
		t.Errorf("expected YubiKey read failure message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_QRGeneration(t *testing.T) {
	got := signFlowErrorMessage(fmt.Errorf("QR generation: encode failed"), nil)
	if !strings.Contains(got, "QR generation failed") {
		t.Errorf("expected QR failure message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_YubiKeyAdapter(t *testing.T) {
	got := signFlowErrorMessage(fmt.Errorf("pcsc daemon not running"), nil)
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected smart card service message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_SignError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	got := signFlowErrorMessage(fmt.Errorf("sign: hardware fault"), logger)
	if !strings.Contains(got, "Signing failed") {
		t.Errorf("expected 'Signing failed' message, got: %q", got)
	}
	// Verify the raw error is logged.
	data, err := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if err != nil {
		t.Fatalf("debug log not created: %v", err)
	}
	if !strings.Contains(string(data), "sign: hardware fault") {
		t.Errorf("debug log should contain raw error, got: %q", string(data))
	}
}

func TestSignFlowErrorMessage_SignError_NoDoublePrefix(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	signFlowErrorMessage(fmt.Errorf("sign: some error"), logger)
	data, err := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if err != nil {
		t.Fatalf("debug log not created: %v", err)
	}
	content := string(data)
	// Should NOT have "sign flow: sign:" double prefix.
	if strings.Contains(content, "sign flow:") {
		t.Errorf("should not have 'sign flow:' prefix for sign: errors, got: %q", content)
	}
}

func TestSignFlowErrorMessage_GenericError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	got := signFlowErrorMessage(fmt.Errorf("something unexpected"), logger)
	if !strings.Contains(got, "Signing failed") {
		t.Errorf("expected signing failed message, got: %q", got)
	}
}

