package gui

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

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
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrSigningCancelled) {
		return "Cancelled."
	}
	return "Batch stopped: " + signFlowErrorMessage(err, logger)
}
