package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// maxHonorDisplay is the maximum number of characters to show for the honor
// field in the history list.
const maxHonorDisplay = 50

// revocationTimeout is the deadline for creating a revocation PR.
const revocationTimeout = 180 * time.Second

// Sentinel errors returned by the history methods. Their text is user-facing.
var (
	// ErrRevocationsNotLoaded is returned by Revoke before the revocation list
	// has loaded.
	ErrRevocationsNotLoaded = errors.New("Revocation data not loaded. Try refreshing.")
	// ErrNothingToExport is returned by IssuanceLogExport when the log holds no
	// records.
	ErrNothingToExport = errors.New("No credentials have been signed on this computer yet.")
)

// Error texts for the issuance log methods.
const (
	// msgIssuanceLogUnreadable is the error text when the issuance log can't
	// be read for an export, duplicate check or record deletion.
	msgIssuanceLogUnreadable = "Could not read the issuance log."
	msgRecordNotInLog        = "This record is no longer in the issuance log."
	msgDeleteFailed          = "Could not delete the record. The issuance log was not changed."
)

// historyState is the issuance history held under App.mu.
type historyState struct {
	records []issuancelog.IssuanceRecord
	// lowerRecipients[i] and summaries[i] are precomputed for records[i] when
	// the log loads, so filtering does not redo them per query.
	lowerRecipients, summaries []string
	revoked                    map[string]bool // keyed by lower-case payload hash
	revocationsLoaded          bool
	revocationsUnavailable     bool // the last revocation-list fetch failed
	loadFailed                 bool // the last log read failed
}

// HistoryRecord is one issuance log record. Timestamp is RFC 3339; Date is
// YYYY-MM-DD; PayloadSHA256 is lower-case hex and identifies the credential
// to Revoke.
type HistoryRecord struct {
	Timestamp       string `json:"timestamp"`
	Recipient       string `json:"recipient"`
	Honor           string `json:"honor"`
	Detail          string `json:"detail"`
	Date            string `json:"date"`
	PayloadSHA256   string `json:"payloadSha256"`
	SignatureB64URL string `json:"signatureB64url"`
}

// historyRecord returns the HistoryRecord for rec. HistoryRecord keeps
// IssuanceRecord's fields (only the JSON tags differ), so a field added to
// one but not the other fails to compile here.
func historyRecord(rec issuancelog.IssuanceRecord) HistoryRecord {
	return HistoryRecord(rec)
}

// issuanceRecord returns the issuance log record for rec.
func issuanceRecord(rec HistoryRecord) issuancelog.IssuanceRecord {
	return issuancelog.IssuanceRecord(rec)
}

// HistoryRow is one issuance record in the history list.
type HistoryRow struct {
	Record  HistoryRecord `json:"record"`
	Summary string        `json:"summary"` // list text; "[REVOKED] " prefix when revoked
	Revoked bool          `json:"revoked"`
}

// HistorySnapshot is the filtered history list. A UI enables Revoke for a
// selected row when RevokeAvailable is set and the row is not Revoked.
type HistorySnapshot struct {
	Rows                   []HistoryRow `json:"rows"` // newest first, filtered by query
	LoadFailed             bool         `json:"loadFailed"`
	RevocationsUnavailable bool         `json:"revocationsUnavailable"`
	RevocationsLoaded      bool         `json:"revocationsLoaded"`
	RevokeAvailable        bool         `json:"revokeAvailable"` // logged in, online and revocations loaded
}

// RevokeStatus is the outcome of a Revoke that did not fail.
type RevokeStatus string

// Revoke outcomes. In each the credential is marked revoked locally.
const (
	RevokeSubmitted      RevokeStatus = "submitted"      // a revocation PR was opened
	RevokeAlreadyRevoked RevokeStatus = "alreadyRevoked" // already in the revocation list
	RevokePending        RevokeStatus = "pending"        // a revocation PR is already open
)

// RevokeResult is a Revoke that did not fail. Title and Message are the
// dialog copy to show.
type RevokeResult struct {
	Status   RevokeStatus `json:"status"`
	PRNumber int          `json:"prNumber"` // submitted only
	URL      string       `json:"url"`      // submitted only; "" unless an https github.com URL
	Title    string       `json:"title"`
	Message  string       `json:"message"`
}

// formatRecordSummary returns a one-line summary for the history list.
func formatRecordSummary(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf("%s | %s | %s", core.FormatDateDisplay(rec.Date), rec.Recipient, truncateRunes(rec.Honor, maxHonorDisplay))
}

// FormatRecordDetail returns a multi-line detail string for the record dialog.
func FormatRecordDetail(rec HistoryRecord) string {
	return fmt.Sprintf(
		"Timestamp: %s\nRecipient: %s\nHonor: %s\nDetail: %s\nDate: %s\nPayload SHA-256: %s\nSignature: %s",
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail, core.FormatDateDisplay(rec.Date),
		rec.PayloadSHA256, rec.SignatureB64URL,
	)
}

// RevokeConfirmText returns the confirmation prompt for revoking rec.
func RevokeConfirmText(rec HistoryRecord) string {
	return fmt.Sprintf("Revoke credential for %s dated %s?\n\nThis cannot be undone.", rec.Recipient, core.FormatDateDisplay(rec.Date))
}

// DeleteConfirmText returns the question asked before deleting rec from the
// issuance log. revoked says the credential is revoked; otherwise
// anotherRemains says another record of the same credential stays in the log,
// and without one the question warns that the credential stays valid and can
// no longer be revoked from the app.
func DeleteConfirmText(rec HistoryRecord, revoked, anotherRemains bool) string {
	date := core.FormatDateDisplay(rec.Date)
	const backup = "\n\nA backup of the log is saved first."
	switch {
	case revoked:
		return fmt.Sprintf("Are you sure you want to delete the record for %s dated %s from this computer's issuance log?", rec.Recipient, date) + backup
	case anotherRemains:
		return fmt.Sprintf("Are you sure you want to delete this record for %s dated %s from this computer's issuance log?"+
			" Another record of this credential remains in the log.", rec.Recipient, date) + backup
	default:
		return fmt.Sprintf("Are you sure you want to delete the record for %s dated %s from this computer's issuance log?"+
			"\n\nThe credential stays valid: anyone with its QR code can still verify it, and once the record is deleted"+
			" it can no longer be revoked from this app. Did you mean to revoke it instead?", rec.Recipient, date) + backup
	}
}

// RecordDeletedText returns the title and message reporting that rec was
// deleted from the issuance log after a backup to backup.
func RecordDeletedText(rec HistoryRecord, backup string) (title, message string) {
	return "Record Deleted", fmt.Sprintf("Deleted the record for %s dated %s. Backup saved to %s.", rec.Recipient, core.FormatDateDisplay(rec.Date), backup)
}

// DuplicatesConfirmText returns the question asked before removing n
// duplicate entries, or "" when there are none.
func DuplicatesConfirmText(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("Found %d duplicate %s. The earliest valid entry of each credential is kept and later copies are removed. A backup of the current log is saved first. Continue?", n, entries(n))
}

// DuplicatesRemovedText reports how many entries were removed and where the
// log was backed up, or returns "" when none were.
func DuplicatesRemovedText(removed int, backup string) string {
	if removed == 0 {
		return ""
	}
	return fmt.Sprintf("Removed %d %s. Backup saved to %s.", removed, entries(removed), backup)
}

// entries is "entry" or "entries" to follow the count n.
func entries(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}

// hasRecords reports whether a log file's contents hold at least one record.
// Unparseable contents count as records so a corrupt log can still be
// exported for inspection.
func hasRecords(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return false
	}
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		return true
	}
	return len(records) > 0
}

// RefreshHistory re-reads the issuance log (emitting EventHistoryChanged),
// then fetches the revocation list (emitting EventRevocationsChanged). A
// failed read keeps the previous records and a failed fetch the previous
// revocations; both are logged and flagged in the HistorySnapshot. A call
// while another refresh is fetching re-reads the log but skips the fetch, so
// fetch results never apply out of order.
func (a *App) RefreshHistory() {
	a.loadHistory()
	if !a.refreshingHistory.CompareAndSwap(false, true) {
		return
	}
	defer a.refreshingHistory.Store(false)

	list, err := registry.FetchRevocationList(a.revocationURL)
	a.mu.Lock()
	if err != nil {
		a.history.revocationsUnavailable = true
	} else {
		a.history.revoked = core.BuildRevocationSet(list)
		a.history.revocationsLoaded = true
		a.history.revocationsUnavailable = false
	}
	a.mu.Unlock()
	if err != nil {
		a.logger.Logf("history: failed to fetch revocation list: %s", core.SanitizeForLog(err.Error()))
	}
	a.events.Emit(EventRevocationsChanged, nil)
}

// loadHistory re-reads the issuance log and emits EventHistoryChanged, after
// the read is applied and its lock released, so a handler may call back into
// the App.
func (a *App) loadHistory() {
	a.readHistory()
	a.events.Emit(EventHistoryChanged, nil)
}

// readHistory re-reads the issuance log into the history. historyLoadMu spans
// the read and the apply, so an older read never replaces a newer one.
func (a *App) readHistory() {
	a.historyLoadMu.Lock()
	defer a.historyLoadMu.Unlock()
	records, err := issuancelog.ReadLog(a.logPath)
	if err != nil {
		a.logger.Logf("history: failed to read log: %s", core.SanitizeForLog(err.Error()))
	}
	var lower, summaries []string
	if err == nil {
		lower = make([]string, len(records))
		summaries = make([]string, len(records))
		for i, rec := range records {
			lower[i] = strings.ToLower(norm.NFC.String(rec.Recipient))
			summaries[i] = formatRecordSummary(rec)
		}
	}
	a.mu.Lock()
	a.history.loadFailed = err != nil
	if err == nil {
		a.history.records, a.history.lowerRecipients, a.history.summaries = records, lower, summaries
	}
	a.mu.Unlock()
}

// History returns the loaded records whose recipient contains query
// (case-insensitive, trimmed, both NFC-normalized so a decomposed accent
// matches; empty matches all), newest first.
func (a *App) History(query string) HistorySnapshot {
	q := strings.ToLower(norm.NFC.String(strings.TrimSpace(query)))
	a.mu.Lock()
	defer a.mu.Unlock()
	h := &a.history
	rows := make([]HistoryRow, 0, len(h.records))
	for i := len(h.records) - 1; i >= 0; i-- {
		if q != "" && !strings.Contains(h.lowerRecipients[i], q) {
			continue
		}
		rec := h.records[i]
		row := HistoryRow{Record: historyRecord(rec), Summary: h.summaries[i], Revoked: core.IsRevoked(rec.PayloadSHA256, h.revoked)}
		if row.Revoked {
			row.Summary = "[REVOKED] " + row.Summary
		}
		rows = append(rows, row)
	}
	return HistorySnapshot{
		Rows:                   rows,
		LoadFailed:             h.loadFailed,
		RevocationsUnavailable: h.revocationsUnavailable,
		RevocationsLoaded:      h.revocationsLoaded,
		RevokeAvailable:        a.loggedIn && !a.githubOffline && h.revocationsLoaded,
	}
}

// Revoke opens a pull request adding the credential with payload hash
// payloadSHA256 to the revocation list. A credential already revoked (locally
// or upstream) or with a revocation PR already open is not a failure: the
// result says so. It returns ErrNotLoggedIn without a usable session,
// ErrRevocationsNotLoaded before the revocation list has loaded, ErrBusy while
// another Revoke runs, and an error matching ErrSessionExpired when GitHub
// rejected the session (it then logs out). Failures are logged; every error's
// text is user-facing and GitHub errors stay wrapped. Revoke emits no history
// events.
func (a *App) Revoke(ctx context.Context, payloadSHA256 string) (RevokeResult, error) {
	if !a.revoking.CompareAndSwap(false, true) {
		return RevokeResult{}, ErrBusy
	}
	defer a.revoking.Store(false)

	hash := strings.ToLower(payloadSHA256)
	a.mu.Lock()
	client, revoked, loaded := a.clientLocked(), a.history.revoked[hash], a.history.revocationsLoaded
	a.mu.Unlock()
	switch {
	case client == nil:
		return RevokeResult{}, ErrNotLoggedIn
	case revoked:
		return RevokeResult{Status: RevokeAlreadyRevoked, Title: "Already Revoked", Message: ghapi.UserMessage(ghapi.ErrAlreadyRevoked)}, nil
	case !loaded:
		return RevokeResult{}, ErrRevocationsNotLoaded
	}

	ctx, cancel := context.WithTimeout(ctx, revocationTimeout)
	defer cancel()
	// ghapi builds the new list from upstream main, so revocations merged
	// since the last fetch are never dropped.
	pr, err := client.CreateRevocationPR(ctx, hash, time.Now().UTC().Format("2006-01-02"))
	var res RevokeResult
	switch {
	case err == nil:
		url := ghapi.GitHubURLOrEmpty(pr.HTMLURL)
		res = RevokeResult{
			Status:   RevokeSubmitted,
			PRNumber: pr.Number,
			URL:      url,
			Title:    "Revocation Submitted",
			Message:  submittedMessage(pr.Number, url),
		}
	case errors.Is(err, ghapi.ErrAlreadyRevoked):
		res = RevokeResult{Status: RevokeAlreadyRevoked, Title: "Already Revoked", Message: ghapi.UserMessage(err)}
	case errors.Is(err, ghapi.ErrRevocationPending):
		res = RevokeResult{Status: RevokePending, Title: "Revocation Pending", Message: ghapi.UserMessage(err)}
	case ghapi.IsUnauthorized(err):
		a.logger.Logf("warning: revocation unauthorized, logging out: %s", core.SanitizeForLog(err.Error()))
		a.Logout()
		return RevokeResult{}, userErr(ErrSessionExpired.Error(), ErrSessionExpired, err)
	default:
		a.logger.Logf("error: revocation PR failed: %s", core.SanitizeForLog(err.Error()))
		return RevokeResult{}, userErr(ghapi.UserMessage(err), err)
	}
	if err != nil {
		// Nothing to submit: the hash is already revoked upstream or awaiting
		// review, so it is marked locally like a success.
		a.logger.Logf("info: revocation not submitted: %s", core.SanitizeForLog(err.Error()))
	}
	a.mu.Lock()
	a.history.revoked[hash] = true // non-nil: the list had loaded
	a.mu.Unlock()
	return res, nil
}

// submittedMessage is the RevokeSubmitted dialog text; url is "" when GitHub
// returned a PR URL that failed validation.
func submittedMessage(prNumber int, url string) string {
	created := fmt.Sprintf("Pull request #%d created.", prNumber)
	if url != "" {
		created = fmt.Sprintf("Pull request #%d created:\n%s", prNumber, url)
	}
	return created + "\n\nIf several revocation PRs are open, merge them one at a time."
}

// IssuanceLogExport returns the raw issuance log for the operator to save.
// It returns ErrNothingToExport when no credential has been logged; other
// errors are logged and their text is user-facing.
func (a *App) IssuanceLogExport() ([]byte, error) {
	data, err := os.ReadFile(a.logPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNothingToExport
	}
	if err != nil {
		a.logger.Logf("history: failed to read log for export: %s", core.SanitizeForLog(err.Error()))
		return nil, userErr(msgIssuanceLogUnreadable, err)
	}
	if !hasRecords(data) {
		return nil, ErrNothingToExport
	}
	return data, nil
}

// ErrorLogExport returns the diagnostic log for the operator to save. Errors
// are logged and their text is user-facing.
func (a *App) ErrorLogExport() ([]byte, error) {
	return a.saver().errorLog()
}

// DuplicatePreview returns how many duplicate entries RemoveDuplicates would
// remove, without changing the log. Errors are logged and their text is
// user-facing.
func (a *App) DuplicatePreview() (int, error) {
	records, err := issuancelog.ReadLog(a.logPath)
	if err != nil {
		a.logger.Logf("history: failed to read log for dedup: %s", core.SanitizeForLog(err.Error()))
		return 0, userErr(msgIssuanceLogUnreadable, err)
	}
	_, n := issuancelog.Dedupe(records)
	return n, nil
}

// RemoveDuplicates rewrites the issuance log without duplicate entries,
// backing it up first, and returns the number removed and the backup path.
// When it removed any, it reloads the history (emitting EventHistoryChanged).
// Errors are logged and their text is user-facing.
func (a *App) RemoveDuplicates() (removed int, backup string, err error) {
	removed, backup, err = issuancelog.RemoveDuplicates(a.logPath)
	if err != nil {
		a.logger.Logf("history: remove duplicates failed: %s", core.SanitizeForLog(err.Error()))
		return 0, "", userErr("Could not remove duplicates. The issuance log was not changed.", err)
	}
	if removed > 0 {
		a.loadHistory()
	}
	return removed, backup, nil
}

// DeleteConfirm returns the question to ask before DeleteEntry deletes rec,
// and whether to offer revoking it instead: true unless rec's credential is
// revoked. Before the revocation list has loaded, or when its first fetch
// failed, every credential counts as not revoked. The question says whether
// another record of the credential remains in the loaded history: one with
// the same payload hash (case-insensitive, never empty) and a well-formed
// signature, other than rec itself.
func (a *App) DeleteConfirm(rec HistoryRecord) (message string, offerRevoke bool) {
	a.mu.Lock()
	revoked := core.IsRevoked(rec.PayloadSHA256, a.history.revoked)
	anotherRemains := !revoked && a.otherCopiesLocked(rec) > 0
	a.mu.Unlock()
	return DeleteConfirmText(rec, revoked, anotherRemains), !revoked
}

// otherCopiesLocked counts the loaded records, other than rec, that are the
// issued credential for rec's payload hash (see issuancelog.IssuedKey).
// Identical copies of rec count; only the first record equal to rec is rec
// itself, and none is when rec is no longer loaded. a.mu must be held.
func (a *App) otherCopiesLocked(rec HistoryRecord) int {
	if rec.PayloadSHA256 == "" {
		return 0
	}
	self := issuanceRecord(rec)
	hash := strings.ToLower(rec.PayloadSHA256)
	n := 0
	skipped := false
	for _, r := range a.history.records {
		if !skipped && r == self {
			skipped = true
			continue
		}
		// The hash check first: IssuedKey decodes the signature.
		if !strings.EqualFold(r.PayloadSHA256, hash) {
			continue
		}
		if _, ok := issuancelog.IssuedKey(r); ok {
			n++
		}
	}
	return n
}

// DeleteEntry deletes the first issuance log record equal to rec (every
// field, exact match), backing the log up first, and returns the backup path.
// It reloads the history (emitting EventHistoryChanged) after deleting and
// when no record matched; the latter returns an error matching ErrNotFound.
// Errors are logged and their text is user-facing.
func (a *App) DeleteEntry(rec HistoryRecord) (backup string, err error) {
	backup, err = issuancelog.RemoveRecord(a.logPath, issuanceRecord(rec))
	switch {
	case err == nil:
		a.loadHistory()
		return backup, nil
	case errors.Is(err, issuancelog.ErrRecordNotFound):
		a.loadHistory()
		return "", userErr(msgRecordNotInLog, ErrNotFound, err)
	case errors.Is(err, issuancelog.ErrLogUnreadable):
		a.logger.Logf("history: failed to read log for delete: %s", core.SanitizeForLog(err.Error()))
		return "", userErr(msgIssuanceLogUnreadable, err)
	default:
		a.logger.Logf("history: delete record failed: %s", core.SanitizeForLog(err.Error()))
		return "", userErr(msgDeleteFailed, err)
	}
}
