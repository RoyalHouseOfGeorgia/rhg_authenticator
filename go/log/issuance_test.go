package log

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
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

func TestIssuedKey(t *testing.T) {
	for _, tc := range []struct {
		name, hash, sig string
		wantKey         string
		wantOK          bool
	}{
		{"mixed-case hash lower-cased", "ABcd", sigOf(1), "abcd", true},
		{"empty hash", "", sigOf(1), "", false},
		{"malformed signature", "abcd", "c2ln", "", false},
		{"empty signature", "abcd", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := recWithHash(tc.hash, "A")
			rec.SignatureB64URL = tc.sig
			if key, ok := IssuedKey(rec); key != tc.wantKey || ok != tc.wantOK {
				t.Errorf("IssuedKey = (%q, %v), want (%q, %v)", key, ok, tc.wantKey, tc.wantOK)
			}
		})
	}
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

func TestRemoveDuplicates_InvalidJSONIsUnreadable(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	if err := os.WriteFile(logPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := RemoveDuplicates(logPath); !errors.Is(err, ErrLogUnreadable) {
		t.Errorf("err = %v, want ErrLogUnreadable", err)
	}
}

// writeLogBytes writes data as the log at logPath.
func writeLogBytes(t *testing.T, logPath, data string) {
	t.Helper()
	if err := os.WriteFile(logPath, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// assertUnchanged fails t unless the log at logPath holds want and no backup
// was written.
func assertUnchanged(t *testing.T, logPath, want string) {
	t.Helper()
	got, err := os.ReadFile(logPath)
	if want == "" {
		if !os.IsNotExist(err) {
			t.Errorf("log should not exist, read err = %v", err)
		}
	} else if err != nil || string(got) != want {
		t.Errorf("log = %q, %v; want %q unchanged", got, err, want)
	}
	if baks := backupFiles(t, logPath); len(baks) != 0 {
		t.Errorf("unexpected backup files: %v", baks)
	}
}

func TestRewriteWithBackup_BacksUpOriginalBytes(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	original := "[\n" + `{"recipient":"A","payload_sha256":"aa"},` + "\n" + `{"recipient":"B"}]`
	writeLogBytes(t, logPath, original)

	var seen []IssuanceRecord
	backup, err := rewriteWithBackup(logPath, func(records []IssuanceRecord) ([]IssuanceRecord, bool, error) {
		seen = records
		return records[1:], true, nil
	})
	if err != nil {
		t.Fatalf("rewriteWithBackup: %v", err)
	}
	if len(seen) != 2 || seen[0].Recipient != "A" {
		t.Errorf("transform got %+v", seen)
	}
	if !strings.HasPrefix(backup, logPath+".bak-") || len(backupFiles(t, logPath)) != 1 {
		t.Errorf("backup = %q, files %v", backup, backupFiles(t, logPath))
	}
	bak, err := os.ReadFile(backup)
	if err != nil || string(bak) != original {
		t.Errorf("backup = %q, %v; want the original bytes", bak, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("backup mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}
	got, err := ReadLog(logPath)
	if err != nil || len(got) != 1 || got[0].Recipient != "B" {
		t.Errorf("rewritten log = %+v, %v", got, err)
	}
}

func TestRewriteWithBackup_NothingWritten(t *testing.T) {
	errTransform := errors.New("transform failed")
	for _, tc := range []struct {
		name    string
		content string // "" = no log
		changed bool
		err     error
		wantErr error
	}{
		{"unchanged", `[{"recipient":"A"}]`, false, nil, nil},
		{"transform error", `[{"recipient":"A"}]`, true, errTransform, errTransform},
		{"missing log unchanged", "", false, nil, nil},
		{"missing log transform error", "", false, errTransform, errTransform},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "issuance.json")
			if tc.content != "" {
				writeLogBytes(t, logPath, tc.content)
			}
			var seen []IssuanceRecord
			backup, err := rewriteWithBackup(logPath, func(records []IssuanceRecord) ([]IssuanceRecord, bool, error) {
				seen = records
				return nil, tc.changed, tc.err
			})
			if err != tc.wantErr || backup != "" {
				t.Errorf("got (%q, %v), want (\"\", %v)", backup, err, tc.wantErr)
			}
			if tc.content == "" && (seen == nil || len(seen) != 0) {
				t.Errorf("missing log passed %#v, want an empty list", seen)
			}
			assertUnchanged(t, logPath, tc.content)
		})
	}
}

func TestRewriteWithBackup_Unreadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, logPath string)
	}{
		{"not json", func(t *testing.T, logPath string) { writeLogBytes(t, logPath, "not json") }},
		{"empty file", func(t *testing.T, logPath string) { writeLogBytes(t, logPath, "") }},
		{"directory", func(t *testing.T, logPath string) {
			if err := os.Mkdir(logPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "issuance.json")
			tc.setup(t, logPath)
			called := false
			_, err := rewriteWithBackup(logPath, func(records []IssuanceRecord) ([]IssuanceRecord, bool, error) {
				called = true
				return records, true, nil
			})
			if !errors.Is(err, ErrLogUnreadable) {
				t.Errorf("err = %v, want ErrLogUnreadable", err)
			}
			if called {
				t.Error("transform called on an unreadable log")
			}
			if baks := backupFiles(t, logPath); len(baks) != 0 {
				t.Errorf("unexpected backup files: %v", baks)
			}
		})
	}
}

func TestRewriteWithBackup_BackupFailureLeavesLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "issuance.json")
	const original = `[{"recipient":"A"}]`
	writeLogBytes(t, logPath, original)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := rewriteWithBackup(logPath, func([]IssuanceRecord) ([]IssuanceRecord, bool, error) { return nil, true, nil })
	if err == nil || errors.Is(err, ErrLogUnreadable) || !strings.Contains(err.Error(), "creating backup") {
		t.Errorf("err = %v, want a backup failure", err)
	}
	assertUnchanged(t, logPath, original)
}

func TestCreateBackup_NeverOverwrites(t *testing.T) {
	base := filepath.Join(t.TempDir(), "issuance.json.bak-20260102T030405Z")
	writeLogBytes(t, base, "existing")

	got, err := createBackup(base, []byte("second"))
	if err != nil || got != base+"-2" {
		t.Fatalf("createBackup = %q, %v; want %q", got, err, base+"-2")
	}
	got, err = createBackup(base, []byte("third"))
	if err != nil || got != base+"-3" {
		t.Fatalf("createBackup = %q, %v; want %q", got, err, base+"-3")
	}
	for path, want := range map[string]string{base: "existing", base + "-2": "second", base + "-3": "third"} {
		if data, err := os.ReadFile(path); err != nil || string(data) != want {
			t.Errorf("%s = %q, %v; want %q", path, data, err, want)
		}
	}
}

func TestCreateBackup_CreateError(t *testing.T) {
	base := filepath.Join(t.TempDir(), "missing-dir", "issuance.json.bak-x")
	if _, err := createBackup(base, []byte("x")); err == nil {
		t.Fatal("expected an error creating a backup in a missing directory")
	}
}

func TestRemoveRecord_RemovesFirstEqual(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	target := recWithHash("aa", "Target")
	other := recWithHash("bb", "Other")
	for _, rec := range []IssuanceRecord{other, target, other, target} {
		if err := AppendRecord(logPath, rec); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	original, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	backup, err := RemoveRecord(logPath, target)
	if err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}
	if bak, err := os.ReadFile(backup); err != nil || string(bak) != string(original) {
		t.Errorf("backup = %q, %v; want the original bytes", bak, err)
	}
	got, err := ReadLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := []IssuanceRecord{other, other, target}; !reflect.DeepEqual(got, want) {
		t.Errorf("log = %+v, want %+v", got, want)
	}
}

func TestRemoveRecord_NotFound(t *testing.T) {
	target := recWithHash(strings.Repeat("ab", 32), "Zoe\u0308")
	logged, err := json.Marshal([]IssuanceRecord{target})
	if err != nil {
		t.Fatal(err)
	}
	nearMiss := func(f func(*IssuanceRecord)) IssuanceRecord {
		rec := target
		f(&rec)
		return rec
	}
	for _, tc := range []struct {
		name    string
		content string // "" = no log
		rec     IssuanceRecord
	}{
		{"missing log", "", target},
		{"empty log", "[]", target},
		{"null log", "null", target},
		{"hash case", string(logged), nearMiss(func(r *IssuanceRecord) { r.PayloadSHA256 = strings.ToUpper(r.PayloadSHA256) })},
		{"NFC recipient", string(logged), nearMiss(func(r *IssuanceRecord) { r.Recipient = "Zo\u00eb" })},
		{"timestamp", string(logged), nearMiss(func(r *IssuanceRecord) { r.Timestamp = "2026-01-01T00:00:00Z" })},
		{"trailing space", string(logged), nearMiss(func(r *IssuanceRecord) { r.Detail += " " })},
		{"signature", string(logged), nearMiss(func(r *IssuanceRecord) { r.SignatureB64URL = sigOf(2) })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "issuance.json")
			if tc.content != "" {
				writeLogBytes(t, logPath, tc.content)
			}
			backup, err := RemoveRecord(logPath, tc.rec)
			if !errors.Is(err, ErrRecordNotFound) || backup != "" {
				t.Errorf("got (%q, %v), want ErrRecordNotFound", backup, err)
			}
			assertUnchanged(t, logPath, tc.content)
		})
	}
}

func TestRemoveRecord_Unreadable(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	writeLogBytes(t, logPath, "not json")
	if _, err := RemoveRecord(logPath, sampleRecord()); !errors.Is(err, ErrLogUnreadable) || errors.Is(err, ErrRecordNotFound) {
		t.Errorf("err = %v, want ErrLogUnreadable", err)
	}
	assertUnchanged(t, logPath, "not json")
}

// TestRemoveRecord_ConcurrentWithAppend checks that removals and appends
// serialize on writeMu: no append is lost and nothing deadlocks.
func TestRemoveRecord_ConcurrentWithAppend(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuance.json")
	const n = 10
	victims := make([]IssuanceRecord, n)
	for i := range victims {
		victims[i] = recWithHash(fmt.Sprintf("%064x", i), "victim")
		if err := AppendRecord(logPath, victims[i]); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := RemoveRecord(logPath, victims[i]); err != nil {
				t.Errorf("RemoveRecord: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := AppendRecord(logPath, recWithHash(fmt.Sprintf("%064x", 100+i), "kept")); err != nil {
				t.Errorf("AppendRecord: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := ReadLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("log has %d records, want %d", len(got), n)
	}
	if backups := backupFiles(t, logPath); len(backups) != n {
		t.Errorf("%d backups, want one per removal (%d)", len(backups), n)
	}
	for _, rec := range got {
		if rec.Recipient != "kept" {
			t.Errorf("unexpected record %+v", rec)
		}
	}
}
