package log

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// IssuanceRecord is one entry in the issuance log.
// Security note: PII fields (Recipient, Honor, Detail) are also present in
// the signed credentials published on the verify page. The log adds no
// sensitivity beyond what is already public. Stored with 0o600 on the
// user's local filesystem.
type IssuanceRecord struct {
	Timestamp       string `json:"timestamp"` // RFC 3339 (e.g., "2026-03-13T10:30:00Z")
	Recipient       string `json:"recipient"`
	Honor           string `json:"honor"`
	Detail          string `json:"detail"`
	Date            string `json:"date"`
	PayloadSHA256   string `json:"payload_sha256"` // lowercase hex
	SignatureB64URL string `json:"signature_b64url"`
}

// writeMu serializes log writes (AppendRecord, RemoveDuplicates) so a
// read-modify-write cannot interleave with another and lose records.
var writeMu sync.Mutex

// AppendRecord atomically appends a record to the issuance log, creating it if
// it doesn't exist. It reads the entire log, appends, and rewrites (see
// writeLog): O(n), but acceptable for the expected volume (~100s of records),
// and incremental append would sacrifice atomic-write crash safety.
//
// Serialized in-process with RemoveDuplicates by writeMu; exclusion across
// processes relies on Fyne's single-instance app ID.
func AppendRecord(logPath string, record IssuanceRecord) error {
	writeMu.Lock()
	defer writeMu.Unlock()

	records, err := ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("reading existing log: %w", err)
	}

	records = append(records, record)
	return writeLog(logPath, records)
}

// writeLog atomically replaces the log with records via temp file + rename.
func writeLog(logPath string, records []IssuanceRecord) error {
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
	return parseLog(data)
}

func parseLog(data []byte) ([]IssuanceRecord, error) {
	var records []IssuanceRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parsing log file: %w", err)
	}
	return records, nil
}

// SignatureWellFormed reports whether sigB64 decodes to an Ed25519-sized
// signature. A record failing this never counts as the issued credential for
// its hash, here or in the Sign tab's duplicate check.
func SignatureWellFormed(sigB64 string) bool {
	sig, err := core.Decode(sigB64)
	return err == nil && len(sig) == ed25519.SignatureSize
}

// Dedupe returns records with later copies of the same payload hash
// (case-insensitive) dropped, keeping the earliest well-formed record by log
// order, and the number dropped. Records with an empty hash are always kept,
// and a malformed record is kept without claiming its hash, so a valid
// re-signed copy after it survives.
func Dedupe(records []IssuanceRecord) (kept []IssuanceRecord, removed int) {
	seen := make(map[string]bool, len(records))
	kept = make([]IssuanceRecord, 0, len(records))
	for _, rec := range records {
		if rec.PayloadSHA256 != "" {
			key := strings.ToLower(rec.PayloadSHA256)
			if seen[key] {
				removed++
				continue
			}
			if SignatureWellFormed(rec.SignatureB64URL) {
				seen[key] = true
			}
		}
		kept = append(kept, rec)
	}
	return kept, removed
}

// RemoveDuplicates rewrites the log without duplicate records (see
// Dedupe). Before rewriting, the original bytes are saved to a
// timestamped ".bak-" file next to the log; if that fails the log is left
// untouched. Writes nothing when there are no duplicates or no log.
func RemoveDuplicates(logPath string) (removed int, backupPath string, err error) {
	writeMu.Lock()
	defer writeMu.Unlock()

	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, "", nil
		}
		return 0, "", fmt.Errorf("reading log file: %w", err)
	}
	records, err := parseLog(data)
	if err != nil {
		return 0, "", err
	}

	kept, removed := Dedupe(records)
	if removed == 0 {
		return 0, "", nil
	}

	backupPath = logPath + ".bak-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		return 0, "", fmt.Errorf("writing backup: %w", err)
	}
	if err := writeLog(logPath, kept); err != nil {
		return 0, "", err
	}
	return removed, backupPath, nil
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
