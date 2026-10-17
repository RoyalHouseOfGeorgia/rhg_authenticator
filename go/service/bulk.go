package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
// row against the audit log at logPath. Input and parse errors are returned
// as-is (their messages are user-facing). An unreadable audit log is fatal:
// without it, already-issued credentials cannot be detected.
func loadBulkPlan(r io.Reader, logPath string) ([]bulk.Result, error) {
	data, err := bulk.ReadInput(r)
	if err != nil {
		return nil, err
	}
	rows, err := bulk.ParseCSV(data, bulk.MaxRows)
	if err != nil {
		return nil, err
	}
	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read audit log; bulk signing needs it to avoid duplicates: %w", err)
	}
	issued := make(map[string]string, len(records))
	for _, rec := range records {
		issued[rec.PayloadSHA256] = rec.SignatureB64URL
	}
	return bulk.Plan(rows, honorTitles, issued), nil
}

// runBulkFlow signs every to_sign row in results, updating them in place.
//
// The PIN is resolved once per batch, before any card access. Each row still
// opens a fresh adapter (see signAndLog), so no exclusive PCSC transaction is
// held across rows. Every early return marks leftover rows not_attempted.
func runBulkFlow(
	ctx context.Context,
	results []bulk.Result,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	readPin func() (string, error),
	onConnecting func(),
	onProgress func(done, total int, name string),
	logger *debuglog.Logger,
) error {
	if logPath == "" {
		bulk.MarkNotAttempted(results)
		return errors.New("audit log path is not configured")
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
			return signAndLog(req, logPath, openAdapter, pin, logger)
		},
		func(e error) string { return signFlowErrorMessage(e, logger) },
		onProgress,
	)
}

// bulkStopMessage returns the user-facing reason a batch stopped early, or ""
// when it completed.
func bulkStopMessage(err error, logger *debuglog.Logger) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, errSigningCancelled) {
		return "Cancelled."
	}
	return "Batch stopped: " + signFlowErrorMessage(err, logger)
}

// saveBulkResults renders results as CSV and writes them to path.
func saveBulkResults(path string, results []bulk.Result) error {
	var buf bytes.Buffer
	if err := bulk.WriteResultCSV(&buf, results); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
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

// BulkResultsFilename returns the default export name for a results CSV,
// timestamped in UTC.
func BulkResultsFilename(t time.Time) string {
	return t.UTC().Format("rhg-bulk-results-2006-01-02-150405.csv")
}
