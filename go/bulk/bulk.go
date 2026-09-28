package bulk

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// Row statuses. StatusToSign is an internal planning state that never
// survives a completed Run or a MarkNotAttempted call.
const (
	StatusSigned        = "signed"
	StatusAlreadyIssued = "already_issued"
	StatusInvalid       = "invalid"
	StatusFailed        = "failed"
	StatusNotAttempted  = "not_attempted"
	StatusToSign        = "to_sign"
)

// errNotLoggedMsg is the per-row message for a credential signed without an
// audit-log record.
const errNotLoggedMsg = "signed but NOT recorded in audit log"

// Result is the outcome for one input row. Req holds the trimmed request
// that is signed and exported; Hash is the payload SHA-256 hex when the row
// passed validation.
type Result struct {
	Row
	Req    core.SignRequest
	Hash   string
	Status string
	URL    string
	Err    string
}

// Plan validates rows and classifies each as to_sign, already_issued, or
// invalid. issued maps payload SHA-256 hex to the stored base64url signature.
func Plan(rows []Row, allowedHonors []string, issued map[string]string) []Result {
	results := make([]Result, len(rows))
	seen := make(map[string]int)
	for i, row := range rows {
		res := Result{
			Row: row,
			Req: core.SignRequest{
				Recipient: strings.TrimSpace(row.Name),
				Honor:     strings.TrimSpace(row.Honor),
				Detail:    strings.TrimSpace(row.Detail),
				Date:      strings.TrimSpace(row.Date),
			},
			Status: StatusInvalid,
		}
		results[i] = res
		if row.ParseErr != "" {
			results[i].Err = row.ParseErr
			continue
		}
		if looksMisencoded(res.Req) {
			results[i].Err = "text looks mis-encoded (contains \"??\") — re-save the file as CSV UTF-8"
			continue
		}
		if !slices.Contains(allowedHonors, res.Req.Honor) {
			results[i].Err = `honor: not one of the allowed honor titles: "` + strings.Join(allowedHonors, `", "`) + `"`
			continue
		}
		payload, err := core.BuildPayload(res.Req)
		if err != nil {
			results[i].Err = core.SanitizeForError(err.Error())
			continue
		}
		hash := core.PayloadSHA256Hex(payload)
		results[i].Hash = hash
		if line, dup := seen[hash]; dup {
			results[i].Err = fmt.Sprintf("duplicate of line %d (same credential)", line)
			continue
		}
		seen[hash] = row.Line
		if sig, ok := issued[hash]; ok {
			results[i].Status = StatusAlreadyIssued
			results[i].URL = core.BuildVerifyURL(core.Encode(payload), sig)
			continue
		}
		results[i].Status = StatusToSign
	}
	return results
}

// looksMisencoded reports whether any field shows the marks of text that lost
// its encoding: Excel's plain "CSV" save turns non-Latin script (e.g. Georgian)
// into runs of "?", and a failed decode leaves U+FFFD. Such text is valid, so
// without this check it would be signed irreversibly.
func looksMisencoded(req core.SignRequest) bool {
	for _, f := range []string{req.Recipient, req.Honor, req.Detail, req.Date} {
		if strings.Contains(f, "??") || strings.ContainsRune(f, utf8.RuneError) {
			return true
		}
	}
	return false
}

// Run signs every to_sign row in order, updating results in place. It stops
// at the first error, marking the remaining rows not_attempted, and returns
// that error unchanged. A cancelled ctx is honoured between rows; a row that
// is already signing is allowed to finish.
func Run(
	ctx context.Context,
	results []Result,
	signFn func(core.SignRequest) (core.SignResponse, error),
	describe func(error) string,
	onProgress func(done, total int, name string),
) error {
	total := 0
	for _, r := range results {
		if r.Status == StatusToSign {
			total++
		}
	}
	done := 0
	for i := range results {
		r := &results[i]
		if r.Status != StatusToSign {
			continue
		}
		if err := ctx.Err(); err != nil {
			MarkNotAttempted(results)
			return err
		}
		onProgress(done, total, r.Req.Recipient)
		resp, err := signFn(r.Req)
		switch {
		case err == nil:
			r.Status = StatusSigned
			r.URL = resp.URL
			done++
		case errors.Is(err, core.ErrNotLogged):
			r.Status = StatusSigned
			r.URL = resp.URL
			r.Err = errNotLoggedMsg
			MarkNotAttempted(results)
			return err
		default:
			r.Status = StatusFailed
			r.Err = describe(err)
			MarkNotAttempted(results)
			return err
		}
	}
	return nil
}

// MarkNotAttempted changes every remaining to_sign row to not_attempted.
func MarkNotAttempted(results []Result) {
	for i := range results {
		if results[i].Status == StatusToSign {
			results[i].Status = StatusNotAttempted
		}
	}
}

// WriteResultCSV writes results as a UTF-8 CSV (with BOM, for Excel) with
// columns name, honor, detail, date, url, status, error.
func WriteResultCSV(w io.Writer, results []Result) error {
	if _, err := w.Write(utf8BOM); err != nil {
		return err
	}
	records := make([][]string, 0, len(results)+1)
	records = append(records, []string{"name", "honor", "detail", "date", "url", "status", "error"})
	for _, r := range results {
		records = append(records, []string{r.Req.Recipient, r.Req.Honor, r.Req.Detail, r.Req.Date, r.URL, r.Status, r.Err})
	}
	return csv.NewWriter(w).WriteAll(records)
}

// Counts tallies results by status.
type Counts struct {
	Total         int
	Signed        int
	AlreadyIssued int
	Invalid       int
	Failed        int
	NotAttempted  int
	ToSign        int
}

// Successful returns the number of rows that have a valid credential URL.
func (c Counts) Successful() int {
	return c.Signed + c.AlreadyIssued
}

// Summarize counts results by status.
func Summarize(results []Result) Counts {
	c := Counts{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusSigned:
			c.Signed++
		case StatusAlreadyIssued:
			c.AlreadyIssued++
		case StatusInvalid:
			c.Invalid++
		case StatusFailed:
			c.Failed++
		case StatusNotAttempted:
			c.NotAttempted++
		case StatusToSign:
			c.ToSign++
		}
	}
	return c
}
