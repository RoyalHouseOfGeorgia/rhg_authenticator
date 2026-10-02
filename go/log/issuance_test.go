package log

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// sampleRecord returns a valid IssuanceRecord for testing.
func sampleRecord() IssuanceRecord {
	return IssuanceRecord{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Recipient:       "John Doe",
		Honor:           "Order of the Golden Fleece",
		Detail:          "Awarded for distinguished service",
		Date:            "2026-03-13",
		PayloadSHA256:   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		SignatureB64URL: "c2lnbmF0dXJl",
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
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
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
		Timestamp:       "2026-03-13T10:30:00Z",
		Recipient:       "Jane",
		Honor:           "Medal",
		Detail:          "For valor",
		Date:            "2026-03-13",
		PayloadSHA256:   "aabbccdd",
		SignatureB64URL: "c2ln",
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
		"date", "payload_sha256", "signature_b64url",
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

	for i, err := range errs {
		if err != nil {
			t.Errorf("AppendRecord #%d: %v", i, err)
		}
	}

	// writeMu serializes the read-modify-write, so every record must land.
	records, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog after concurrent writes failed: %v", err)
	}
	if len(records) != n {
		t.Fatalf("got %d records after %d concurrent appends, want %d", len(records), n, n)
	}
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
	if !strings.Contains(content, "  \"timestamp\"") {
		t.Errorf("expected 2-space indented fields in JSON output")
	}
}

func TestReadLog_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
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

// recWithHash returns a sample record for hash with a well-formed (64-byte)
// signature, so Dedupe treats it as an issued credential.
func recWithHash(hash, recipient string) IssuanceRecord {
	rec := sampleRecord()
	rec.PayloadSHA256 = hash
	rec.Recipient = recipient
	rec.SignatureB64URL = sigOf(1)
	return rec
}

// sigOf returns a well-formed base64url signature filled with b.
func sigOf(b byte) string {
	return core.Encode(bytes.Repeat([]byte{b}, ed25519.SignatureSize))
}

func TestDedupe_None(t *testing.T) {
	records := []IssuanceRecord{recWithHash("aa", "A"), recWithHash("bb", "B")}
	kept, removed := Dedupe(records)
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if !reflect.DeepEqual(kept, records) {
		t.Errorf("kept = %+v, want %+v", kept, records)
	}
}

func TestDedupe_PairKeepsFirst(t *testing.T) {
	records := []IssuanceRecord{recWithHash("aa", "first"), recWithHash("bb", "B"), recWithHash("aa", "second")}
	kept, removed := Dedupe(records)
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	want := records[:2]
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %+v, want %+v", kept, want)
	}
}

func TestDedupe_ThreeCopies(t *testing.T) {
	records := []IssuanceRecord{recWithHash("aa", "1"), recWithHash("aa", "2"), recWithHash("aa", "3")}
	kept, removed := Dedupe(records)
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if len(kept) != 1 || kept[0].Recipient != "1" {
		t.Errorf("kept = %+v, want only the first record", kept)
	}
}

func TestDedupe_CaseInsensitiveHash(t *testing.T) {
	records := []IssuanceRecord{recWithHash("ABCDEF", "upper"), recWithHash("abcdef", "lower")}
	kept, removed := Dedupe(records)
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(kept) != 1 || kept[0].Recipient != "upper" {
		t.Errorf("kept = %+v, want only the uppercase (first) record", kept)
	}
}

func TestDedupe_DifferentSignaturesKeepsFirst(t *testing.T) {
	first := recWithHash("aa", "A")
	first.SignatureB64URL = sigOf(1)
	second := recWithHash("aa", "A")
	second.SignatureB64URL = sigOf(2)
	kept, removed := Dedupe([]IssuanceRecord{first, second})
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if len(kept) != 1 || kept[0].SignatureB64URL != sigOf(1) {
		t.Errorf("kept = %+v, want only the first signature", kept)
	}
}

func TestDedupe_MalformedFirstKeepsLaterValid(t *testing.T) {
	malformed := recWithHash("aa", "bad")
	malformed.SignatureB64URL = "c2ln" // decodes, but not 64 bytes
	valid := recWithHash("aa", "good")
	later := recWithHash("aa", "copy")
	kept, removed := Dedupe([]IssuanceRecord{malformed, valid, later})
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	want := []IssuanceRecord{malformed, valid}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %+v, want malformed + first valid", kept)
	}
}

func TestDedupe_EmptyHashAlwaysKept(t *testing.T) {
	records := []IssuanceRecord{recWithHash("", "A"), recWithHash("", "B")}
	kept, removed := Dedupe(records)
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if !reflect.DeepEqual(kept, records) {
		t.Errorf("kept = %+v, want %+v", kept, records)
	}
}

// backupFiles returns the .bak- files next to logPath.
func backupFiles(t *testing.T, logPath string) []string {
	t.Helper()
	matches, err := filepath.Glob(logPath + ".bak-*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return matches
}

func TestRemoveDuplicates_NoDuplicatesNoOp(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")
	if err := AppendRecord(logPath, recWithHash("aa", "A")); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}
	if err := AppendRecord(logPath, recWithHash("bb", "B")); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	removed, backup, err := RemoveDuplicates(logPath)
	if err != nil {
		t.Fatalf("RemoveDuplicates: %v", err)
	}
	if removed != 0 || backup != "" {
		t.Errorf("got (%d, %q), want (0, \"\")", removed, backup)
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(before) {
		t.Error("log bytes changed on no-op")
	}
	if baks := backupFiles(t, logPath); len(baks) != 0 {
		t.Errorf("unexpected backup files: %v", baks)
	}
}

func TestRemoveDuplicates_RemovesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "issuance.json")
	records := []IssuanceRecord{
		recWithHash("aa", "1"),
		recWithHash("bb", "2"),
		recWithHash("AA", "3"),
		recWithHash("bb", "4"),
		recWithHash("", "5"),
		recWithHash("aa", "6"),
	}
	for _, rec := range records {
		if err := AppendRecord(logPath, rec); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	original, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	removed, backup, err := RemoveDuplicates(logPath)
	if err != nil {
		t.Fatalf("RemoveDuplicates: %v", err)
	}
	if removed != 3 {
		t.Errorf("removed = %d, want 3", removed)
	}
	if !strings.HasPrefix(backup, logPath+".bak-") {
		t.Errorf("backup path = %q, want prefix %q", backup, logPath+".bak-")
	}
	bakData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("reading backup: %v", err)
	}
	if string(bakData) != string(original) {
		t.Error("backup bytes differ from original log bytes")
	}

	got, err := ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	want := []IssuanceRecord{records[0], records[1], records[4]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rewritten log = %+v, want %+v", got, want)
	}
}

func TestRemoveDuplicates_MissingFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	removed, backup, err := RemoveDuplicates(logPath)
	if err != nil || removed != 0 || backup != "" {
		t.Errorf("got (%d, %q, %v), want (0, \"\", nil)", removed, backup, err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("log file should not be created, stat err = %v", err)
	}
}

func TestRemoveDuplicates_InvalidJSON(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	if err := os.WriteFile(logPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := RemoveDuplicates(logPath); err == nil {
		t.Fatal("expected parse error")
	}
	if baks := backupFiles(t, logPath); len(baks) != 0 {
		t.Errorf("unexpected backup files: %v", baks)
	}
}
