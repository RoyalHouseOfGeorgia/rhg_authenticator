package log

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

// writeMu serializes log writes (AppendRecord, and RemoveDuplicates and
// RemoveRecord through rewriteWithBackup) so a read-modify-write cannot
// interleave with another and lose records.
var writeMu sync.Mutex

// Errors returned by the log rewrites.
var (
	// ErrLogUnreadable is matched by a RemoveDuplicates or RemoveRecord error
	// when the log exists but can't be read or parsed.
	ErrLogUnreadable = errors.New("issuance log unreadable")
	// ErrRecordNotFound is returned by RemoveRecord when no record is equal to
	// the one to remove.
	ErrRecordNotFound = errors.New("record not in the issuance log")
)

// AppendRecord atomically appends a record to the issuance log, creating it if
// it doesn't exist. It reads the entire log, appends, and rewrites (see
// writeLog): O(n), but acceptable for the expected volume (~100s of records),
// and incremental append would sacrifice atomic-write crash safety.
//
// Serialized in-process with RemoveDuplicates and RemoveRecord by writeMu;
// exclusion across processes relies on a single running instance of the app.
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

// IssuedKey returns rec's payload hash lower-cased, and whether rec can be the
// issued credential for that hash: the hash is non-empty and the signature is
// well-formed. Dedupe, the Sign tab's duplicate check and the History delete
// question all count records by this rule.
func IssuedKey(rec IssuanceRecord) (key string, ok bool) {
	if rec.PayloadSHA256 == "" || !SignatureWellFormed(rec.SignatureB64URL) {
		return "", false
	}
	return strings.ToLower(rec.PayloadSHA256), true
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
		if seen[strings.ToLower(rec.PayloadSHA256)] {
			removed++
			continue
		}
		if key, ok := IssuedKey(rec); ok {
			seen[key] = true
		}
		kept = append(kept, rec)
	}
	return kept, removed
}

// RemoveDuplicates rewrites the log without duplicate records (see
// Dedupe), backing it up first (see rewriteWithBackup). Writes nothing when
// there are no duplicates or no log.
func RemoveDuplicates(logPath string) (removed int, backupPath string, err error) {
	backupPath, err = rewriteWithBackup(logPath, func(records []IssuanceRecord) ([]IssuanceRecord, bool, error) {
		var kept []IssuanceRecord
		kept, removed = Dedupe(records)
		return kept, removed > 0, nil
	})
	if err != nil {
		return 0, "", err
	}
	return removed, backupPath, nil
}

// RemoveRecord rewrites the log without the first record equal to rec (every
// field, exact string equality), backing it up first (see rewriteWithBackup).
// It returns ErrRecordNotFound, writing nothing, when no record is equal,
// including when there is no log.
func RemoveRecord(logPath string, rec IssuanceRecord) (backupPath string, err error) {
	return rewriteWithBackup(logPath, func(records []IssuanceRecord) ([]IssuanceRecord, bool, error) {
		i := slices.Index(records, rec)
		if i < 0 {
			return nil, false, ErrRecordNotFound
		}
		return slices.Delete(records, i, i+1), true, nil
	})
}

// rewriteWithBackup applies transform to the log's records under writeMu. A
// missing log reads as no records; a log that can't be read or parsed is an
// error matching ErrLogUnreadable. transform's error is returned unwrapped.
// When transform reports a change, the log's original bytes are saved to a
// new backup (see createBackup) before the log is rewritten; if the backup
// fails the log is left untouched. It returns the backup path, or "" when
// nothing changed.
func rewriteWithBackup(logPath string, transform func([]IssuanceRecord) ([]IssuanceRecord, bool, error)) (backupPath string, err error) {
	writeMu.Lock()
	defer writeMu.Unlock()

	records := []IssuanceRecord{}
	data, err := os.ReadFile(logPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return "", fmt.Errorf("%w: reading log file: %w", ErrLogUnreadable, err)
	default:
		if records, err = parseLog(data); err != nil {
			return "", fmt.Errorf("%w: %w", ErrLogUnreadable, err)
		}
	}

	out, changed, err := transform(records)
	if err != nil || !changed {
		return "", err
	}
	backupPath, err = createBackup(logPath+".bak-"+time.Now().UTC().Format("20060102T150405Z"), data)
	if err != nil {
		return "", err
	}
	if err := writeLog(logPath, out); err != nil {
		return "", err
	}
	return backupPath, nil
}

// createBackup writes data to a new 0600 file at base, or at base-2, base-3,
// … when that exists, so no earlier backup is ever overwritten. A file it
// created but could not finish writing is removed. It returns the path
// written.
func createBackup(base string, data []byte) (string, error) {
	path := base
	for n := 2; ; n++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			path = fmt.Sprintf("%s-%d", base, n)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("creating backup: %w", err)
		}
		_, werr := f.Write(data)
		if err := errors.Join(werr, f.Close()); err != nil {
			os.Remove(path)
			return "", fmt.Errorf("writing backup: %w", err)
		}
		return path, nil
	}
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
