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

// HistoryRow is one issuance record in the history list.
type HistoryRow struct {
	Record  issuancelog.IssuanceRecord
	Summary string // list text; "[REVOKED] " prefix when revoked
	Revoked bool
}

// HistorySnapshot is the filtered history list. A UI enables Revoke for a
// selected row when RevokeAvailable is set and the row is not Revoked.
type HistorySnapshot struct {
	Rows                               []HistoryRow // newest first, filtered by query
	LoadFailed, RevocationsUnavailable bool
	RevocationsLoaded                  bool
	RevokeAvailable                    bool // logged in, online and revocations loaded
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
	Status         RevokeStatus
	PRNumber       int    // submitted only
	URL            string // submitted only; "" unless an https github.com URL
	Title, Message string
}

// formatRecordSummary returns a one-line summary for the history list.
func formatRecordSummary(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf("%s | %s | %s", core.FormatDateDisplay(rec.Date), rec.Recipient, truncateRunes(rec.Honor, maxHonorDisplay))
}

// FormatRecordDetail returns a multi-line detail string for the record dialog.
func FormatRecordDetail(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf(
		"Timestamp: %s\nRecipient: %s\nHonor: %s\nDetail: %s\nDate: %s\nPayload SHA-256: %s\nSignature: %s",
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail, core.FormatDateDisplay(rec.Date),
		rec.PayloadSHA256, rec.SignatureB64URL,
	)
}

// RevokeConfirmText returns the confirmation prompt for revoking rec.
func RevokeConfirmText(rec issuancelog.IssuanceRecord) string {
	return fmt.Sprintf("Revoke credential for %s dated %s?\n\nThis cannot be undone.", rec.Recipient, core.FormatDateDisplay(rec.Date))
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

// loadHistory re-reads the issuance log and emits EventHistoryChanged.
// historyLoadMu spans the read and the apply, so an older read never
// replaces a newer one.
func (a *App) loadHistory() {
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
			lower[i] = strings.ToLower(rec.Recipient)
			summaries[i] = formatRecordSummary(rec)
		}
	}
	a.mu.Lock()
	a.history.loadFailed = err != nil
	if err == nil {
		a.history.records, a.history.lowerRecipients, a.history.summaries = records, lower, summaries
	}
	a.mu.Unlock()
	a.events.Emit(EventHistoryChanged, nil)
}

// History returns the loaded records whose recipient contains query
// (case-insensitive, trimmed; empty matches all), newest first.
func (a *App) History(query string) HistorySnapshot {
	q := strings.ToLower(strings.TrimSpace(query))
	a.mu.Lock()
	defer a.mu.Unlock()
	h := &a.history
	rows := make([]HistoryRow, 0, len(h.records))
	for i := len(h.records) - 1; i >= 0; i-- {
		if q != "" && !strings.Contains(h.lowerRecipients[i], q) {
			continue
		}
		rec := h.records[i]
		row := HistoryRow{Record: rec, Summary: h.summaries[i], Revoked: core.IsRevoked(rec.PayloadSHA256, h.revoked)}
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
		RevokeAvailable:        a.loggedIn && !a.offline && h.revocationsLoaded,
	}
}

// Revoke opens a pull request adding the credential with payload hash
// payloadSHA256 to the revocation list. A credential already revoked (locally
// or upstream) or with a revocation PR already open is not a failure: the
// result says so. It returns ErrNotLoggedIn without a usable session,
// ErrRevocationsNotLoaded before the revocation list has loaded, ErrBusy while
// another Revoke runs, and a GitHub error detectable with ghapi.IsUnauthorized
// when the session expired (it then logs out). Failures are logged;
// RevokeErrorMessage gives the text to show. Revoke emits no history events.
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
		url := pr.HTMLURL
		if ghapi.ParseGitHubURL(url) == nil {
			url = ""
		}
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
		return RevokeResult{}, err
	default:
		a.logger.Logf("error: revocation PR failed: %s", core.SanitizeForLog(err.Error()))
		return RevokeResult{}, err
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

// RevokeErrorMessage returns the dialog title and message for a Revoke error.
func RevokeErrorMessage(err error) (title, msg string) {
	switch {
	case ghapi.IsUnauthorized(err):
		return "Session Expired", "Your GitHub session expired. Please log in again."
	case errors.Is(err, ErrRevocationsNotLoaded):
		return "Revocation Failed", ErrRevocationsNotLoaded.Error()
	case errors.Is(err, ErrNotLoggedIn):
		return "Revocation Failed", ErrNotLoggedIn.Error()
	default:
		return "Revocation Failed", ghapi.UserMessage(err)
	}
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
		return nil, errors.New("could not read the issuance log")
	}
	if !hasRecords(data) {
		return nil, ErrNothingToExport
	}
	return data, nil
}

// ErrorLogExport returns the diagnostic log for the operator to save. Errors
// are logged and their text is user-facing.
func (a *App) ErrorLogExport() ([]byte, error) {
	data, err := os.ReadFile(a.logger.Path())
	if err != nil {
		a.logger.Logf("errorlog: failed to read log for export: %s", core.SanitizeForLog(err.Error()))
		return nil, errors.New("could not read the error log")
	}
	return data, nil
}

// DuplicatePreview returns how many duplicate entries RemoveDuplicates would
// remove, without changing the log. Errors are logged and their text is
// user-facing.
func (a *App) DuplicatePreview() (int, error) {
	records, err := issuancelog.ReadLog(a.logPath)
	if err != nil {
		a.logger.Logf("history: failed to read log for dedup: %s", core.SanitizeForLog(err.Error()))
		return 0, errors.New("Could not read the issuance log.")
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
		return 0, "", errors.New("Could not remove duplicates. The issuance log was not changed.")
	}
	if removed > 0 {
		a.loadHistory()
	}
	return removed, backup, nil
}
