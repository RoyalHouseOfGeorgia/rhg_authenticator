package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// sampleRecord returns a valid IssuanceRecord for testing.
func sampleRecord() IssuanceRecord {
	return IssuanceRecord{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Recipient:     "John Doe",
		Honor:         "Order of the Golden Fleece",
		Detail:        "Awarded for distinguished service",
		Date:          "2026-03-13",
		Authority:     "Royal House of Georgia",
		PayloadSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		SignatureB64URL:  "c2lnbmF0dXJl",
	}
}

func TestAppendRecord_NewFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	rec := sampleRecord()
	if err := AppendRecord(logPath, rec); err != nil {
		t.Fatalf("AppendRecord failed: %v", err)
	}

	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Recipient != "John Doe" {
		t.Errorf("recipient = %q, want %q", records[0].Recipient, "John Doe")
	}
	if records[0].Honor != "Order of the Golden Fleece" {
		t.Errorf("honor = %q, want %q", records[0].Honor, "Order of the Golden Fleece")
	}
}

func TestAppendRecord_TwoRecords(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	rec1 := sampleRecord()
	rec1.Recipient = "Alice"
	rec2 := sampleRecord()
	rec2.Recipient = "Bob"

	if err := AppendRecord(logPath, rec1); err != nil {
		t.Fatalf("first AppendRecord failed: %v", err)
	}
	if err := AppendRecord(logPath, rec2); err != nil {
		t.Fatalf("second AppendRecord failed: %v", err)
	}

	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Recipient != "Alice" {
		t.Errorf("first recipient = %q, want %q", records[0].Recipient, "Alice")
	}
	if records[1].Recipient != "Bob" {
		t.Errorf("second recipient = %q, want %q", records[1].Recipient, "Bob")
	}
}

func TestReadLog_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "does_not_exist.json")

	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice, got %d records", len(records))
	}
}

func TestReadLog_ValidFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	rec := sampleRecord()
	data, err := json.MarshalIndent([]IssuanceRecord{rec}, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Detail != rec.Detail {
		t.Errorf("detail = %q, want %q", records[0].Detail, rec.Detail)
	}
}

func TestReadLog_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	if err := os.WriteFile(logPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	_, err := ReadLog(logPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAppendRecord_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	if err := AppendRecord(logPath, sampleRecord()); err != nil {
		t.Fatalf("AppendRecord failed: %v", err)
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// On Linux, os.Rename preserves the tmp file permissions.
	// The tmp file is written with 0o600, so the final file should be 0o600.
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions = %o, want 600", perm)
	}
}

func TestCleanStaleTmpFiles_RemovesMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	// Create stale tmp files.
	tmp1 := filepath.Join(dir, "issuance.json.tmp.abc12345")
	tmp2 := filepath.Join(dir, "issuance.json.tmp.def67890")
	if err := os.WriteFile(tmp1, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write tmp1 failed: %v", err)
	}
	if err := os.WriteFile(tmp2, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write tmp2 failed: %v", err)
	}

	if err := CleanStaleTmpFiles(logPath); err != nil {
		t.Fatalf("CleanStaleTmpFiles failed: %v", err)
	}

	// Verify tmp files are gone.
	if _, err := os.Stat(tmp1); !os.IsNotExist(err) {
		t.Errorf("tmp1 should have been removed")
	}
	if _, err := os.Stat(tmp2); !os.IsNotExist(err) {
		t.Errorf("tmp2 should have been removed")
	}
}

func TestCleanStaleTmpFiles_PreservesUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	// Create an unrelated file and a file for a different log name.
	unrelated := filepath.Join(dir, "other_file.txt")
	differentLog := filepath.Join(dir, "other.json.tmp.abc12345")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write unrelated failed: %v", err)
	}
	if err := os.WriteFile(differentLog, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write differentLog failed: %v", err)
	}

	if err := CleanStaleTmpFiles(logPath); err != nil {
		t.Fatalf("CleanStaleTmpFiles failed: %v", err)
	}

	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file should still exist: %v", err)
	}
	if _, err := os.Stat(differentLog); err != nil {
		t.Errorf("different log tmp file should still exist: %v", err)
	}
}

func TestCleanStaleTmpFiles_NonexistentDirectory(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "nonexistent_subdir", "issuance.json")

	err := CleanStaleTmpFiles(logPath)
	if err != nil {
		t.Fatalf("expected no error for nonexistent directory, got %v", err)
	}
}

func TestIssuanceRecord_JSONKeys(t *testing.T) {
	rec := IssuanceRecord{
		Timestamp:     "2026-03-13T10:30:00Z",
		Recipient:     "Jane",
		Honor:         "Medal",
		Detail:        "For valor",
		Date:          "2026-03-13",
		Authority:     "Crown",
		PayloadSHA256: "aabbccdd",
		SignatureB64URL:  "c2ln",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	expectedKeys := []string{
		"timestamp", "recipient", "honor", "detail",
		"date", "authority", "payload_sha256", "signature_b64url",
	}
	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}
	if len(m) != len(expectedKeys) {
		t.Errorf("expected %d keys, got %d", len(expectedKeys), len(m))
	}
}

func TestAppendRecord_TimestampRFC3339(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	ts := "2026-03-13T10:30:00Z"
	rec := sampleRecord()
	rec.Timestamp = ts

	if err := AppendRecord(logPath, rec); err != nil {
		t.Fatalf("AppendRecord failed: %v", err)
	}

	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// Verify the timestamp is valid RFC 3339.
	parsed, err := time.Parse(time.RFC3339, records[0].Timestamp)
	if err != nil {
		t.Fatalf("timestamp %q is not valid RFC 3339: %v", records[0].Timestamp, err)
	}
	if parsed.Year() != 2026 || parsed.Month() != 3 || parsed.Day() != 13 {
		t.Errorf("parsed timestamp date mismatch: %v", parsed)
	}
}

func TestAppendRecord_ConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := sampleRecord()
			rec.Recipient = "Recipient-" + string(rune('A'+idx))
			errs[idx] = AppendRecord(logPath, rec)
		}(i)
	}
	wg.Wait()

	// At least some should succeed. Due to races, not all may land,
	// but we should not lose the file or get corruption.
	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog after concurrent writes failed: %v", err)
	}

	// The file should be valid JSON with at least 1 record.
	if len(records) < 1 {
		t.Fatalf("expected at least 1 record after concurrent writes, got %d", len(records))
	}

	// In a serial scenario all n would be present. With concurrent access
	// and no locking, some may be lost (read-modify-write race), but the
	// file must remain valid JSON (atomic rename guarantees this).
	t.Logf("concurrent writes: %d/%d records survived", len(records), n)
}

func TestAppendRecord_JSONFormatPrettyPrinted(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	if err := AppendRecord(logPath, sampleRecord()); err != nil {
		t.Fatalf("AppendRecord failed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	content := string(data)
	// Pretty-printed JSON starts with "[\n  {" (2-space indent).
	if len(content) < 5 || content[0] != '[' || content[1] != '\n' {
		t.Errorf("expected pretty-printed JSON, got: %.40s...", content)
	}
	// Should contain 2-space indentation.
	if !contains(content, "  \"timestamp\"") {
		t.Errorf("expected 2-space indented fields in JSON output")
	}
}

// contains is a simple helper to avoid importing strings in tests.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestReadLog_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	// Create a file, then make it unreadable.
	if err := os.WriteFile(logPath, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(logPath, 0o000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	t.Cleanup(func() { os.Chmod(logPath, 0o600) })

	_, err := ReadLog(logPath)
	if err == nil {
		t.Fatal("expected error for unreadable file, got nil")
	}
}

func TestAppendRecord_ReadError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	// Write invalid JSON so ReadLog will fail on the existing file.
	if err := os.WriteFile(logPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	err := AppendRecord(logPath, sampleRecord())
	if err == nil {
		t.Fatal("expected error when existing log has invalid JSON, got nil")
	}
}

func TestAppendRecord_WriteError(t *testing.T) {
	// logPath points to a non-writable directory, so WriteFile will fail.
	dir := t.TempDir()
	subdir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(subdir, 0o500); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	t.Cleanup(func() { os.Chmod(subdir, 0o700) })

	logPath := filepath.Join(subdir, "issuance.json")
	err := AppendRecord(logPath, sampleRecord())
	if err == nil {
		t.Fatal("expected error writing to read-only directory, got nil")
	}
}

func TestCleanStaleTmpFiles_DirectoryWithSubdirs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")

	// Create a subdirectory that matches the prefix pattern — should be skipped.
	subdir := filepath.Join(dir, "issuance.json.tmp.subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	if err := CleanStaleTmpFiles(logPath); err != nil {
		t.Fatalf("CleanStaleTmpFiles failed: %v", err)
	}

	// The subdirectory should still exist (dirs are skipped).
	if _, err := os.Stat(subdir); err != nil {
		t.Errorf("subdirectory should still exist: %v", err)
	}
}

func TestRandomHex_Length(t *testing.T) {
	h, err := randomHex(8)
	if err != nil {
		t.Fatalf("randomHex failed: %v", err)
	}
	if len(h) != 8 {
		t.Errorf("expected 8 hex chars, got %d: %q", len(h), h)
	}
}

func TestRandomHex_OddLength(t *testing.T) {
	h, err := randomHex(7)
	if err != nil {
		t.Fatalf("randomHex failed: %v", err)
	}
	if len(h) != 7 {
		t.Errorf("expected 7 hex chars, got %d: %q", len(h), h)
	}
}
