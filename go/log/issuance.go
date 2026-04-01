package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// IssuanceRecord is one entry in the issuance log.
// Security note: PII fields (Recipient, Honor, Detail) are also present in
// the signed credentials published on the verify page. The log adds no
// sensitivity beyond what is already public. Stored with 0o600 on the
// user's local filesystem.
type IssuanceRecord struct {
	Timestamp     string `json:"timestamp"`       // RFC 3339 (e.g., "2026-03-13T10:30:00Z")
	Recipient     string `json:"recipient"`
	Honor         string `json:"honor"`
	Detail        string `json:"detail"`
	Date          string `json:"date"`
	PayloadSHA256 string `json:"payload_sha256"`  // lowercase hex
	SignatureB64URL string `json:"signature_b64url"`
}

// AppendRecord reads the entire log, appends, and rewrites. This is O(n) but
// acceptable for the expected volume (~100s of records). The read-all-then-rewrite
// pattern is intentional: incremental append would sacrifice atomic-write crash
// safety for a performance gain not needed at current scale.
//
// REQUIRES: caller must serialize calls (not concurrent-safe). Enforced by
// Fyne single-instance guarantee (app ID) and YubiKey mutex-serialized signing.
//
// AppendRecord atomically appends a record to the issuance log.
// Uses a temp file + rename pattern for crash safety.
// Creates the log file if it doesn't exist.
func AppendRecord(logPath string, record IssuanceRecord) error {
	records, err := ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("reading existing log: %w", err)
	}

	records = append(records, record)

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling records: %w", err)
	}
	data = append(data, '\n')

	suffix, err := core.RandomHex(16)
	if err != nil {
		return fmt.Errorf("generating tmp suffix: %w", err)
	}

	tmpPath := logPath + ".tmp." + suffix
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing tmp file: %w", err)
	}

	if err := os.Rename(tmpPath, logPath); err != nil {
		// Best-effort cleanup of the tmp file.
		os.Remove(tmpPath)
		return fmt.Errorf("renaming tmp file: %w", err)
	}

	return nil
}

// ReadLog reads all records from the issuance log.
// Returns empty slice (not error) if the file doesn't exist.
func ReadLog(logPath string) ([]IssuanceRecord, error) {
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []IssuanceRecord{}, nil
		}
		return nil, fmt.Errorf("reading log file: %w", err)
	}

	var records []IssuanceRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parsing log file: %w", err)
	}

	return records, nil
}

// CleanStaleTmpFiles removes any stale .tmp.* files in the log directory.
// Call on app startup.
func CleanStaleTmpFiles(logPath string) error {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)
	prefix := base + ".tmp."

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading log directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), prefix) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing stale tmp file %s: %w", entry.Name(), err)
			}
		}
	}

	return nil
}

