package gui

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// authErrSignAdapter has a valid ExportPublicKey but fails SignBytes with a
// PIV PIN authentication error, as a wrong PIN would.
type authErrSignAdapter struct {
	secretKey ed25519.PrivateKey
}

func (a *authErrSignAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], a.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (a *authErrSignAdapter) SignBytes(data []byte) ([]byte, error) {
	return nil, piv.AuthErr{Retries: 2}
}

// bulkHarness bundles a temp audit log, debug logger, and call-counting
// openAdapter/readPin fakes backed by an in-test ed25519 key.
type bulkHarness struct {
	logPath   string
	logger    *debuglog.Logger
	priv      ed25519.PrivateKey
	opens     int
	pinReads  int
	pinErr    error
	newSigner func(ed25519.PrivateKey) core.SigningAdapter
}

func newBulkHarness(t *testing.T) *bulkHarness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	return &bulkHarness{
		logPath: filepath.Join(dir, "issuances.json"),
		logger:  debuglog.New(filepath.Join(dir, "debug.log")),
		priv:    priv,
		newSigner: func(k ed25519.PrivateKey) core.SigningAdapter {
			return &mockSignAdapter{secretKey: k}
		},
	}
}

func (h *bulkHarness) openAdapter(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
	h.opens++
	return h.newSigner(h.priv), nopCloser{}, nil
}

func (h *bulkHarness) readPin() (string, error) {
	h.pinReads++
	if h.pinErr != nil {
		return "", h.pinErr
	}
	return "123456", nil
}

func (h *bulkHarness) run(t *testing.T, ctx context.Context, results []bulk.Result, onProgress func(done, total int, name string)) error {
	t.Helper()
	if onProgress == nil {
		onProgress = func(int, int, string) {}
	}
	return runBulkFlow(ctx, results, h.logPath, h.openAdapter, h.readPin, nil, onProgress, h.logger)
}

func (h *bulkHarness) plan(t *testing.T, csvText string) []bulk.Result {
	t.Helper()
	results, err := loadBulkPlan(strings.NewReader(csvText), h.logPath)
	if err != nil {
		t.Fatalf("loadBulkPlan: %v", err)
	}
	return results
}

func (h *bulkHarness) logCount(t *testing.T) int {
	t.Helper()
	records, err := issuancelog.ReadLog(h.logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	return len(records)
}

func assertCountsInvariant(t *testing.T, results []bulk.Result) bulk.Counts {
	t.Helper()
	c := bulk.Summarize(results)
	if c.ToSign != 0 {
		t.Errorf("%d rows left to_sign", c.ToSign)
	}
	if sum := c.Signed + c.AlreadyIssued + c.Invalid + c.Failed + c.NotAttempted; sum != c.Total {
		t.Errorf("counts sum %d != total %d (%+v)", sum, c.Total, c)
	}
	return c
}

func statuses(results []bulk.Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Status
	}
	return out
}

func assertStatuses(t *testing.T, results []bulk.Result, want ...string) {
	t.Helper()
	got := statuses(results)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("statuses = %v, want %v", got, want)
	}
}

const threeRowCSV = "name,honor,detail,date\n" +
	"Alice,Other,Service,2026-03-14\n" +
	"Bob,Appointment,Advisor,2026-03-14\n" +
	"Dave,Other,Help,2026-03-14\n"

func TestBulkFlow_EndToEndReRunIsIdempotent(t *testing.T) {
	const csvText = "name,honor,detail,date\n" +
		"Alice,Other,Service,2026-03-14\n" +
		"Bob,Appointment,Advisor,2026-03-14\n" +
		"Carol,Not A Title,Whatever,2026-03-14\n" +
		"Alice,Other,Service,2026-03-14\n" +
		"Dave,Other,Help,2026-03-14\n"
	h := newBulkHarness(t)

	first := h.plan(t, csvText)
	if err := h.run(t, context.Background(), first, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	assertStatuses(t, first,
		bulk.StatusSigned, bulk.StatusSigned, bulk.StatusInvalid, bulk.StatusInvalid, bulk.StatusSigned)
	c := assertCountsInvariant(t, first)
	if c.Signed != 3 {
		t.Errorf("Signed = %d, want 3", c.Signed)
	}
	for _, i := range []int{0, 1, 4} {
		if first[i].URL == "" {
			t.Errorf("row %d: empty URL", i)
		}
	}
	if !strings.Contains(first[3].Err, "duplicate of line") {
		t.Errorf("row 3 Err = %q, want duplicate", first[3].Err)
	}
	if n := h.logCount(t); n != 3 {
		t.Errorf("log records = %d, want 3", n)
	}
	if h.pinReads != 1 || h.opens != 3 {
		t.Errorf("pinReads=%d opens=%d, want 1 and 3", h.pinReads, h.opens)
	}

	h.pinReads, h.opens = 0, 0
	second := h.plan(t, csvText)
	if err := h.run(t, context.Background(), second, nil); err != nil {
		t.Fatalf("second run: %v", err)
	}
	assertStatuses(t, second,
		bulk.StatusAlreadyIssued, bulk.StatusAlreadyIssued, bulk.StatusInvalid, bulk.StatusInvalid, bulk.StatusAlreadyIssued)
	for _, i := range []int{0, 1, 4} {
		if second[i].URL != first[i].URL {
			t.Errorf("row %d URL changed:\n first=%s\nsecond=%s", i, first[i].URL, second[i].URL)
		}
	}
	if n := h.logCount(t); n != 3 {
		t.Errorf("log records after re-run = %d, want 3", n)
	}
	if h.pinReads != 0 || h.opens != 0 {
		t.Errorf("re-run touched the card: pinReads=%d opens=%d", h.pinReads, h.opens)
	}
}

func TestBulkFlow_SingleSignInterop(t *testing.T) {
	h := newBulkHarness(t)
	req := core.SignRequest{
		Recipient: "José Pérez",
		Honor:     "Other",
		Detail:    "Café service",
		Date:      "2026-03-14",
	}
	single, err := executeSignFlow(req, h.logPath, h.openAdapter, h.readPin, nil, h.logger)
	if err != nil {
		t.Fatalf("executeSignFlow: %v", err)
	}

	// Same credential, whitespace-padded, recipient/detail in NFD form.
	csvText := "name,honor,detail,date\n" +
		"  José Pérez  , Other ,  Café service ,2026-03-14 \n"
	results := h.plan(t, csvText)
	assertStatuses(t, results, bulk.StatusAlreadyIssued)
	if results[0].URL != single.Response.URL {
		t.Errorf("URL mismatch:\n  bulk=%s\nsingle=%s", results[0].URL, single.Response.URL)
	}
}

func TestBulkFlow_ReadPinCalledOncePerBatch(t *testing.T) {
	h := newBulkHarness(t)
	connecting := 0
	var progress []int
	results := h.plan(t, threeRowCSV)
	err := runBulkFlow(context.Background(), results, h.logPath, h.openAdapter, h.readPin,
		func() { connecting++ },
		func(done, total int, name string) {
			if total != 3 {
				t.Errorf("total = %d, want 3", total)
			}
			progress = append(progress, done)
		},
		h.logger)
	if err != nil {
		t.Fatalf("runBulkFlow: %v", err)
	}
	if h.pinReads != 1 {
		t.Errorf("readPin called %d times, want 1", h.pinReads)
	}
	if h.opens != 3 {
		t.Errorf("openAdapter called %d times, want 3 (fresh per row)", h.opens)
	}
	if connecting != 1 {
		t.Errorf("onConnecting called %d times, want 1", connecting)
	}
	if len(progress) != 3 {
		t.Errorf("onProgress calls = %v, want 3", progress)
	}
	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusSigned, bulk.StatusSigned)
}

func TestBulkFlow_WrongPINStopsAndClearsCache(t *testing.T) {
	h := newBulkHarness(t)
	h.newSigner = func(k ed25519.PrivateKey) core.SigningAdapter { return &authErrSignAdapter{secretKey: k} }
	results := h.plan(t, threeRowCSV)

	err := h.run(t, context.Background(), results, nil)
	var authErr piv.AuthErr
	if !errors.As(err, &authErr) {
		t.Fatalf("errors.As(err, piv.AuthErr) = false; err = %v", err)
	}
	assertStatuses(t, results, bulk.StatusFailed, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	if !strings.Contains(results[0].Err, "Incorrect PIN") {
		t.Errorf("row 0 Err = %q, want Incorrect PIN message", results[0].Err)
	}
	assertCountsInvariant(t, results)
	if h.opens != 1 {
		t.Errorf("openAdapter called %d times, want 1", h.opens)
	}

	cache := seedEnabledCache(t)
	clearPINCacheOnAuthError(err, cache)
	if _, ok := cache.Get(); ok {
		t.Error("expected PIN cache cleared after bulk auth error")
	}
}

func TestLoadBulkPlan_UnreadableLogRefuses(t *testing.T) {
	results, err := loadBulkPlan(strings.NewReader(threeRowCSV), t.TempDir())
	if err == nil {
		t.Fatal("expected error for a directory log path")
	}
	if !strings.HasPrefix(err.Error(), "cannot read audit log; bulk signing needs it to avoid duplicates") {
		t.Errorf("err = %q", err)
	}
	if results != nil {
		t.Errorf("results = %v, want nil", results)
	}
}

func TestLoadBulkPlan_InputErrorsPropagate(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "issuances.json")
	cases := []struct {
		name, input, want string
	}{
		{"empty", "", "file is empty"},
		{"missing header", "name,honor,detail\nA,Other,x\n", `missing required column "date"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := loadBulkPlan(strings.NewReader(tc.input), logPath)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
			if results != nil {
				t.Errorf("results = %v, want nil", results)
			}
		})
	}
}

func TestBulkFlow_LogAppendFailureStopsBatch(t *testing.T) {
	h := newBulkHarness(t)
	results := h.plan(t, threeRowCSV)
	h.logPath = filepath.Join(t.TempDir(), "missing", "log.json")

	err := h.run(t, context.Background(), results, nil)
	if !errors.Is(err, core.ErrNotLogged) {
		t.Fatalf("errors.Is(err, ErrNotLogged) = false; err = %v", err)
	}
	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	if results[0].URL == "" {
		t.Error("row 0: expected URL for signed-but-unlogged credential")
	}
	if results[0].Err != "signed but NOT recorded in audit log" {
		t.Errorf("row 0 Err = %q", results[0].Err)
	}
	assertCountsInvariant(t, results)
	if msg := bulkStopMessage(err, h.logger); !strings.HasPrefix(msg, "Batch stopped: Credential signed but NOT recorded") {
		t.Errorf("bulkStopMessage = %q", msg)
	}
}

func TestBulkFlow_EmptyLogPathRefuses(t *testing.T) {
	h := newBulkHarness(t)
	results := h.plan(t, threeRowCSV)
	h.logPath = ""

	err := h.run(t, context.Background(), results, nil)
	if err == nil || err.Error() != "audit log path is not configured" {
		t.Fatalf("err = %v", err)
	}
	if h.pinReads != 0 || h.opens != 0 {
		t.Errorf("pinReads=%d opens=%d, want 0", h.pinReads, h.opens)
	}
	assertStatuses(t, results, bulk.StatusNotAttempted, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	assertCountsInvariant(t, results)
}

func TestBulkFlow_ReadPinErrorSignsNothing(t *testing.T) {
	for _, pinErr := range []error{ErrSigningCancelled, ErrPINEntryTimedOut} {
		t.Run(pinErr.Error(), func(t *testing.T) {
			h := newBulkHarness(t)
			h.pinErr = pinErr
			results := h.plan(t, threeRowCSV)

			err := h.run(t, context.Background(), results, nil)
			if err != pinErr {
				t.Fatalf("err = %v, want %v unchanged", err, pinErr)
			}
			if h.pinReads != 1 || h.opens != 0 {
				t.Errorf("pinReads=%d opens=%d, want 1 and 0", h.pinReads, h.opens)
			}
			c := assertCountsInvariant(t, results)
			if c.Signed != 0 || c.NotAttempted != 3 {
				t.Errorf("counts = %+v, want 0 signed, 3 not_attempted", c)
			}
			if n := h.logCount(t); n != 0 {
				t.Errorf("log records = %d, want 0", n)
			}
		})
	}
}

func TestBulkFlow_CancelDuringProgress(t *testing.T) {
	h := newBulkHarness(t)
	results := h.plan(t, threeRowCSV)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancelling while row 2 is announced lets row 2 finish; row 3 is skipped.
	err := h.run(t, ctx, results, func(done, total int, name string) {
		if done == 1 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusSigned, bulk.StatusNotAttempted)
	assertCountsInvariant(t, results)
	if msg := bulkStopMessage(err, h.logger); msg != "Cancelled." {
		t.Errorf("bulkStopMessage = %q, want Cancelled.", msg)
	}
	if n := h.logCount(t); n != 2 {
		t.Errorf("log records = %d, want 2", n)
	}
}

func TestBulkStopMessage(t *testing.T) {
	logger := debuglog.New(filepath.Join(t.TempDir(), "debug.log"))
	if got := bulkStopMessage(nil, logger); got != "" {
		t.Errorf("nil: got %q, want empty", got)
	}
	if got := bulkStopMessage(context.Canceled, logger); got != "Cancelled." {
		t.Errorf("context.Canceled: got %q", got)
	}
	if got := bulkStopMessage(ErrSigningCancelled, logger); got != "Cancelled." {
		t.Errorf("ErrSigningCancelled: got %q", got)
	}
	if got := bulkStopMessage(errors.New("something odd"), logger); !strings.HasPrefix(got, "Batch stopped: ") {
		t.Errorf("generic: got %q, want 'Batch stopped: ' prefix", got)
	}
}
