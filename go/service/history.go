package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// maxHonorDisplay is the maximum number of characters to show for the honor
// field in the history list.
const maxHonorDisplay = 50

// ShouldEnableRevoke reports whether the Revoke button should be enabled: a
// usable GitHub client exists, the revocation list has loaded, a record is
// selected, and that record is not already revoked. cacheReady keeps the button
// state in sync with the OnTapped precondition (which needs the revocation list
// loaded) — without it, selecting a row after a failed fetch would enable a
// button whose tap dead-ends in the "Revocation unavailable" error. Pure and
// nil-safe — callable with selected == nil (the login-state refresh case).
func ShouldEnableRevoke(clientNil, cacheReady bool, selected *issuancelog.IssuanceRecord, revoked map[string]bool) bool {
	return !clientNil && cacheReady && selected != nil && !revoked[strings.ToLower(selected.PayloadSHA256)]
}

// RevokeFailureAction classifies a revocation-PR error: a 401 means the
// session expired (caller restarts login); an already-revoked or pending
// revocation is not a failure and returns a non-empty infoTitle (caller shows
// an information dialog and marks the record revoked); anything else maps to
// a user-facing message.
func RevokeFailureAction(err error) (unauthorized bool, infoTitle, msg string) {
	if ghapi.IsUnauthorized(err) {
		return true, "", "Your GitHub session expired. Please log in again."
	}
	if errors.Is(err, ghapi.ErrAlreadyRevoked) {
		return false, "Already Revoked", ghapi.UserMessage(err)
	}
	if errors.Is(err, ghapi.ErrRevocationPending) {
		return false, "Revocation Pending", ghapi.UserMessage(err)
	}
	return false, "", ghapi.UserMessage(err)
}

// FilterRecords returns records matching the query (case-insensitive substring
// match on recipient), in reverse chronological order (newest first).
func FilterRecords(records []issuancelog.IssuanceRecord, query string) []issuancelog.IssuanceRecord {
	lowerQuery := strings.ToLower(strings.TrimSpace(query))
	n := len(records)
	result := make([]issuancelog.IssuanceRecord, 0, n)

	// Iterate in reverse for newest-first ordering.
	for i := n - 1; i >= 0; i-- {
		rec := records[i]
		if lowerQuery == "" || strings.Contains(strings.ToLower(rec.Recipient), lowerQuery) {
			result = append(result, rec)
		}
	}
	return result
}

// formatRecordSummary returns a one-line summary for the history list.
func formatRecordSummary(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf("%s | %s | %s", core.FormatDateDisplay(rec.Date), rec.Recipient, truncateRunes(rec.Honor, maxHonorDisplay))
}

// FormatRecordSummaryWithRevocation wraps formatRecordSummary, prefixing
// "[REVOKED] " when the record's payload hash appears in the revoked set.
func FormatRecordSummaryWithRevocation(rec issuancelog.IssuanceRecord, revokedHashes map[string]bool) string {
	summary := formatRecordSummary(rec)
	if revokedHashes[strings.ToLower(rec.PayloadSHA256)] {
		return "[REVOKED] " + summary
	}
	return summary
}

// FormatRecordDetail returns a multi-line detail string for the record dialog.
func FormatRecordDetail(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf(
		"Timestamp: %s\nRecipient: %s\nHonor: %s\nDetail: %s\nDate: %s\nPayload SHA-256: %s\nSignature: %s",
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail, core.FormatDateDisplay(rec.Date),
		rec.PayloadSHA256, rec.SignatureB64URL,
	)
}

// HasRecords reports whether a log file's contents hold at least one record.
// Unparseable contents count as records so a corrupt log can still be
// exported for inspection.
func HasRecords(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return false
	}
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		return true
	}
	return len(records) > 0
}
