package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// bulkPreviewNames is how many to_sign recipient names the confirm dialog
// shows, so the operator can spot a mis-encoded file before signing.
const bulkPreviewNames = 5

// loadBulkPlan reads and parses the operator's CSV from r and classifies each
// row against the issuance log at logPath. Input and parse errors keep bulk's
// text (it describes the file to the operator) as a sentence. An unreadable
// issuance log is fatal: without it, already-issued credentials cannot be
// detected. Every error is logged and wraps its cause.
func loadBulkPlan(r io.Reader, logPath string, logger *debuglog.Logger) ([]bulk.Result, error) {
	fail := func(msg string, err error) error {
		logger.Log("bulk load: " + core.SanitizeForLog(err.Error()))
		return userErr(msg, err)
	}
	data, err := bulk.ReadInput(r)
	if err != nil {
		return nil, fail(sentence(err.Error()), err)
	}
	rows, err := bulk.ParseCSV(data, bulk.MaxRows)
	if err != nil {
		return nil, fail(sentence(err.Error()), err)
	}
	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		return nil, fail("Cannot read the issuance log; bulk signing needs it to avoid duplicates.", err)
	}
	issued := make(map[string]string, len(records))
	for _, rec := range records {
		issued[rec.PayloadSHA256] = rec.SignatureB64URL
	}
	return bulk.Plan(rows, honorTitles, issued), nil
}

// runBulkFlow signs every to_sign row in results, updating them in place.
//
// First the card's key is read once (no PIN) and checked against every
// to_sign row with checkKey; a refused row fails with checkKey's message and
// the batch goes on without it. The PIN is then resolved once per batch, and
// not at all when no row is left. Each row still opens a fresh adapter (see
// signAndLog), so no exclusive PCSC transaction is held across rows. Every
// early return marks leftover rows not_attempted.
func runBulkFlow(
	ctx context.Context,
	results []bulk.Result,
	logPath string,
	openAdapter adapterOpener,
	checkKey keyChecker,
	readPin func() (string, error),
	onConnecting func(),
	onProgress func(done, total int, name string),
	logger *debuglog.Logger,
) error {
	if bulk.Summarize(results).ToSign == 0 {
		return nil
	}
	pub, err := readCardKey(openAdapter, logger)
	if err != nil {
		bulk.MarkNotAttempted(results)
		return err
	}
	for i := range results {
		r := &results[i]
		if r.Status != bulk.StatusToSign {
			continue
		}
		if err := checkKey(pub, r.Req); err != nil {
			logKeyRejected(logger, fmt.Sprintf("bulk key check: line %d: ", r.Line), err)
			r.Status, r.Err = bulk.StatusFailed, signFlowErrorMessage(err, logger)
		}
	}
	if bulk.Summarize(results).ToSign == 0 {
		return nil
	}
	pin, err := readPin()
	if err != nil {
		bulk.MarkNotAttempted(results)
		return err
	}
	if onConnecting != nil {
		onConnecting()
	}
	return bulk.Run(ctx, results,
		func(req core.SignRequest) (core.SignResponse, error) {
			return signAndLog(req, logPath, openAdapter, checkKey, pin, logger)
		},
		func(e error) string { return signFlowErrorMessage(e, logger) },
		onProgress,
	)
}

// bulkStop classifies runBulkFlow's error.
func bulkStop(err error) BulkStop {
	switch {
	case err == nil:
		return BulkCompleted
	case errors.Is(err, context.Canceled) || errors.Is(err, errSigningCancelled):
		return BulkCancelled
	default:
		return BulkFailed
	}
}

// bulkStopMessage returns the user-facing reason a batch stopped early, or ""
// when it completed; stop is bulkStop(err).
func bulkStopMessage(stop BulkStop, err error, logger *debuglog.Logger) string {
	switch stop {
	case BulkCompleted:
		return ""
	case BulkCancelled:
		return "Cancelled."
	default:
		return "Batch stopped: " + signFlowErrorMessage(err, logger)
	}
}

// bulkResultsCSV renders results as CSV.
func bulkResultsCSV(results []bulk.Result) ([]byte, error) {
	var buf bytes.Buffer
	if err := bulk.WriteResultCSV(&buf, results); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// bulkSummaryLine formats the per-status tally shown after a batch.
func bulkSummaryLine(c bulk.Counts) string {
	return fmt.Sprintf("Processed %d rows: %d successful (%d newly signed, %d already issued), %d invalid, %d failed/not attempted.",
		c.Total, c.Successful(), c.Signed, c.AlreadyIssued, c.Invalid, c.Failed+c.NotAttempted)
}

// bulkConfirmText returns the confirm dialog's counts line, up to
// bulkPreviewNames to_sign recipient names, and one "line N: <error>" entry
// per invalid row.
func bulkConfirmText(results []bulk.Result) (counts string, preview []string, invalid []string) {
	c := bulk.Summarize(results)
	counts = fmt.Sprintf("%d rows: %d to sign, %d already issued, %d invalid", c.Total, c.ToSign, c.AlreadyIssued, c.Invalid)
	for _, r := range results {
		switch r.Status {
		case bulk.StatusToSign:
			if len(preview) < bulkPreviewNames {
				preview = append(preview, r.Req.Recipient)
			}
		case bulk.StatusInvalid:
			invalid = append(invalid, fmt.Sprintf("line %d: %s", r.Line, r.Err))
		}
	}
	return counts, preview, invalid
}

// bulkFailedLines returns one "line N: <error>" entry per failed row.
func bulkFailedLines(results []bulk.Result) []string {
	var failed []string
	for _, r := range results {
		if r.Status == bulk.StatusFailed {
			failed = append(failed, fmt.Sprintf("line %d: %s", r.Line, r.Err))
		}
	}
	return failed
}

// bulkResultsFilename returns the default export name for a results CSV,
// timestamped in UTC.
func bulkResultsFilename(t time.Time) string {
	return t.UTC().Format("rhg-bulk-results-2006-01-02-150405.csv")
}
