package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/bulk"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// keyEntry is a registry entry for priv's key with the given to date ("" =
// none) and raw allowed_honors JSON ("" = absent).
func keyEntry(priv ed25519.PrivateKey, to, allowed string) core.KeyEntry {
	e := core.KeyEntry{Authority: "A", From: "2025-01-01", PublicKey: pubKeyB64(priv)}
	if to != "" {
		e.To = &to
	}
	if allowed != "" {
		e.Extra = map[string]json.RawMessage{"allowed_honors": json.RawMessage(allowed)}
	}
	return e
}

func pubOf(priv ed25519.PrivateKey) [32]byte {
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return pub
}

const (
	msgExpiredBefore = "This YubiKey's key is valid only until 2026-Mar-13, before the credential date 2026-Mar-14, so the credential would not verify."
	msgOtherOnlyAppt = "This YubiKey's key may not sign “Other” credentials (allowed: Appointment), so the credential would not verify."
)

func TestCheckSigningKey(t *testing.T) {
	_, card, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	undecodable := core.KeyEntry{Authority: "X", From: "2025-01-01", PublicKey: "not base64!"}
	req := core.SignRequest{Recipient: "R", Honor: "Other", Detail: "D", Date: "2026-03-14"}

	for _, tc := range []struct {
		name    string
		entries []core.KeyEntry
		req     core.SignRequest
		reason  error // nil = accepted
		msg     string
	}{
		{"no expiry, unrestricted", []core.KeyEntry{keyEntry(card, "", "")}, req, nil, ""},
		{"key absent", []core.KeyEntry{keyEntry(other, "", "")}, req, ErrKeyNotRegistered, ErrKeyNotRegistered.Error()},
		{"empty registry", nil, req, ErrKeyNotRegistered, ErrKeyNotRegistered.Error()},
		{"undecodable entry skipped", []core.KeyEntry{undecodable, keyEntry(card, "", "")}, req, nil, ""},
		{"only undecodable", []core.KeyEntry{undecodable}, req, ErrKeyNotRegistered, ErrKeyNotRegistered.Error()},
		{"to before the date", []core.KeyEntry{keyEntry(card, "2026-03-13", "")}, req, ErrKeyExpired, msgExpiredBefore},
		{"to equal to the date (inclusive)", []core.KeyEntry{keyEntry(card, "2026-03-14", "")}, req, nil, ""},
		{"backdated: date before from", []core.KeyEntry{func() core.KeyEntry {
			e := keyEntry(card, "", "")
			e.From = "2027-01-01"
			return e
		}()}, req, nil, ""},
		{"honor not allowed", []core.KeyEntry{keyEntry(card, "", `["Appointment"]`)}, req, ErrHonorNotAllowed, msgOtherOnlyAppt},
		{"honor allowed", []core.KeyEntry{keyEntry(card, "", `["Appointment", "Other"]`)}, req, nil, ""},
		{"allowed_honors null", []core.KeyEntry{keyEntry(card, "", `null`)}, req, nil, ""},
		{"allowed_honors empty", []core.KeyEntry{keyEntry(card, "", `[]`)}, req, nil, ""},
		{"allowed_honors all blank", []core.KeyEntry{keyEntry(card, "", `["", " "]`)}, req, nil, ""},
		{"allowed_honors invalid accepts nothing", []core.KeyEntry{keyEntry(card, "", `"Other"`)}, req, ErrHonorNotAllowed,
			"This YubiKey's key may not sign “Other” credentials (allowed: (invalid)), so the credential would not verify."},
		{"allowed_honors untrimmed item accepts nothing", []core.KeyEntry{keyEntry(card, "", `["Other "]`)}, req, ErrHonorNotAllowed,
			"This YubiKey's key may not sign “Other” credentials (allowed: (invalid)), so the credential would not verify."},
		{"honor compared exactly", []core.KeyEntry{keyEntry(card, "", `["other"]`)}, req, ErrHonorNotAllowed,
			"This YubiKey's key may not sign “Other” credentials (allowed: other), so the credential would not verify."},
		{"honor compared in NFC", []core.KeyEntry{keyEntry(card, "", `["Café"]`)},
			core.SignRequest{Recipient: "R", Honor: "Café", Detail: "D", Date: "2026-03-14"}, nil, ""},
		{"precedence: date failure before honor failure", []core.KeyEntry{
			keyEntry(card, "", `["Appointment"]`), keyEntry(card, "2026-03-13", ""),
		}, req, ErrKeyExpired, msgExpiredBefore},
		{"precedence: date failure listed first", []core.KeyEntry{
			keyEntry(card, "2026-03-13", ""), keyEntry(card, "", `["Appointment"]`),
		}, req, ErrKeyExpired, msgExpiredBefore},
		{"precedence: an accepting entry wins", []core.KeyEntry{
			keyEntry(card, "2026-03-13", ""), keyEntry(card, "", `["Appointment"]`), keyEntry(card, "", `["Other"]`),
		}, req, nil, ""},
		{"first date failure supplies the date", []core.KeyEntry{
			keyEntry(card, "2026-03-13", ""), keyEntry(card, "2026-01-01", ""),
		}, req, ErrKeyExpired, msgExpiredBefore},
		{"first honor failure supplies the list", []core.KeyEntry{
			keyEntry(card, "", `["Appointment"]`), keyEntry(card, "", `["Ennoblement"]`),
		}, req, ErrHonorNotAllowed, msgOtherOnlyAppt},
		{"another key's entries ignored", []core.KeyEntry{
			keyEntry(other, "", ""), keyEntry(card, "2026-03-13", ""),
		}, req, ErrKeyExpired, msgExpiredBefore},
		{"malformed date never in range", []core.KeyEntry{keyEntry(card, "", "")},
			core.SignRequest{Recipient: "R", Honor: "Other", Detail: "D", Date: "2026-3-14"}, ErrKeyExpired,
			ErrKeyExpired.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSigningKey(registryWith(tc.entries...), pubOf(card), tc.req)
			if tc.reason == nil {
				if err != nil {
					t.Fatalf("err = %v, want accepted", err)
				}
				return
			}
			var kr *keyRejectedError
			if !errors.As(err, &kr) || !errors.Is(err, tc.reason) {
				t.Fatalf("err = %#v, want a *keyRejectedError matching %v", err, tc.reason)
			}
			if err.Error() != tc.msg {
				t.Errorf("message = %q\n         want %q", err.Error(), tc.msg)
			}
		})
	}
}

func TestLogKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	logger := debuglog.New(path)
	logKeyRejected(logger, "p: ", errors.New("not a key check error"))
	logKeyRejected(logger, "p: ", &keyRejectedError{msg: "Other, 2026-Mar-14", reason: ErrHonorNotAllowed})
	data, _ := os.ReadFile(path)
	if log := string(data); !strings.Contains(log, "p: "+ErrHonorNotAllowed.Error()) ||
		strings.Contains(log, "not a key check error") || strings.Contains(log, "2026-Mar-14") {
		t.Errorf("log = %q, want only the fixed reason", log)
	}
}

func TestKeyRejected_MessagesAndNoReport(t *testing.T) {
	for _, reason := range []error{ErrKeyNotRegistered, ErrKeyExpired, ErrHonorNotAllowed} {
		err := &keyRejectedError{msg: "YubiKey text " + reason.Error(), reason: reason}
		if got := signFlowErrorMessage(err); got != err.msg {
			t.Errorf("signFlowErrorMessage = %q, want %q (not a hardware message)", got, err.msg)
		}
		if offerIssueReport(err) {
			t.Errorf("offerIssueReport(%v) = true", reason)
		}
	}
}

func TestReadCardKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	logger := debuglog.New(filepath.Join(t.TempDir(), "debug.log"))
	var gotPIN string
	var pinErr error
	pub, err := readCardKey(func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		gotPIN, pinErr = rp()
		return &mockSignAdapter{secretKey: priv}, nopCloser{}, nil
	}, logger)
	if err != nil || pub != pubOf(priv) {
		t.Errorf("readCardKey = %x, %v; want the key", pub, err)
	}
	// A PIN request during a key read fails rather than sending an empty PIN.
	if gotPIN != "" || !errors.Is(pinErr, errNoPINForKeyRead) {
		t.Errorf("key read's PIN reader = %q, %v; want errNoPINForKeyRead", gotPIN, pinErr)
	}

	boom := errors.New("pcsc boom")
	if _, err := readCardKey(func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return nil, nil, boom
	}, logger); err != boom {
		t.Errorf("open failure = %v, want it unwrapped", err)
	}

	_, err = readCardKey(func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &errorExportAdapter{}, nopCloser{}, nil
	}, logger)
	var sfe *signFlowError
	if !errors.As(err, &sfe) || sfe.Phase != phaseExportKey {
		t.Errorf("export failure = %v, want phase %s", err, phaseExportKey)
	}
}

// rejectAll is a keyChecker refusing every key as unregistered.
func rejectAll([32]byte, core.SignRequest) error {
	return &keyRejectedError{msg: ErrKeyNotRegistered.Error(), reason: ErrKeyNotRegistered}
}

func TestExecuteSignFlow_KeyRejectedBeforePIN(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")
	var keyReads, signOpens, pinReads int
	readPin := func() (string, error) { pinReads++; return "123456", nil }
	connecting := false

	_, err := executeSignFlow(validSignRequest(), logPath, true, countingOpener(&mockSignAdapter{secretKey: priv}, &keyReads, &signOpens),
		rejectAll, readPin, func() { connecting = true }, logger)
	if !errors.Is(err, ErrKeyNotRegistered) {
		t.Fatalf("err = %v, want ErrKeyNotRegistered", err)
	}
	if keyReads != 1 || signOpens != 0 || pinReads != 0 || connecting {
		t.Errorf("keyReads=%d signOpens=%d pinReads=%d connecting=%v; want only the key read", keyReads, signOpens, pinReads, connecting)
	}
	if _, statErr := os.Stat(logPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("issuance log written: %v", statErr)
	}
	if data, _ := os.ReadFile(filepath.Join(tmpDir, "debug.log")); !strings.Contains(string(data), "key check: "+ErrKeyNotRegistered.Error()) {
		t.Errorf("rejection not logged:\n%s", data)
	}
}

func TestExecuteSignFlow_KeyReadErrorBeforePIN(t *testing.T) {
	pinReads := 0
	readPin := func() (string, error) { pinReads++; return "123456", nil }
	logger := debuglog.New(filepath.Join(t.TempDir(), "debug.log"))
	_, err := executeSignFlow(validSignRequest(), tempLogPath(t), true, func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &errorExportAdapter{}, nopCloser{}, nil
	}, acceptAnyKey, readPin, nil, logger)
	var sfe *signFlowError
	if !errors.As(err, &sfe) || sfe.Phase != phaseExportKey || pinReads != 0 {
		t.Errorf("err = %v, pinReads = %d; want an export_key failure before the PIN", err, pinReads)
	}
}

func TestExecuteSignFlow_ExistingIssuanceSkipsKeyCheck(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")
	req := validSignRequest()
	if _, err := signAndLog(req, logPath, countingOpener(&mockSignAdapter{secretKey: priv}, new(int), new(int)), acceptAnyKey, "123456", logger); err != nil {
		t.Fatal(err)
	}
	var keyReads, signOpens int
	res, err := executeSignFlow(req, logPath, true, countingOpener(&mockSignAdapter{secretKey: priv}, &keyReads, &signOpens), rejectAll, dummyReadPin, nil, logger)
	if err != nil || !res.Existing || keyReads+signOpens != 0 {
		t.Errorf("result = %+v, %v (opens %d); want the logged credential without the card", res, err, keyReads+signOpens)
	}
}

func TestSignAndLog_RechecksTheSigningCard(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "issuances.json")
	signed := false
	adapter := &recordingAdapter{mockSignAdapter: mockSignAdapter{secretKey: priv}, signed: &signed}
	_, err := signAndLog(validSignRequest(), logPath, countingOpener(adapter, new(int), new(int)), rejectAll, "123456",
		debuglog.New(filepath.Join(tmpDir, "debug.log")))
	if !errors.Is(err, ErrKeyNotRegistered) || signed {
		t.Errorf("err = %v, signed = %v; want refused before SignBytes", err, signed)
	}
	if _, statErr := os.Stat(logPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("issuance log written: %v", statErr)
	}
}

// recordingAdapter is a mockSignAdapter that records a SignBytes call.
type recordingAdapter struct {
	mockSignAdapter
	signed *bool
}

func (a *recordingAdapter) SignBytes(data []byte) ([]byte, error) {
	*a.signed = true
	return a.mockSignAdapter.SignBytes(data)
}

// --- bulk ---

func TestBulkFlow_KeyCheckFailsRowsAndContinues(t *testing.T) {
	h := newBulkHarness(t)
	reg := registryWith(keyEntry(h.priv, "", `["Other"]`))
	results := h.plan(t, threeRowCSV) // Alice Other, Bob Appointment, Dave Other
	err := runBulkFlow(context.Background(), results, h.logPath, h.openAdapter,
		func(pub [32]byte, req core.SignRequest) error { return checkSigningKey(reg, pub, req) },
		h.readPin, nil, func(int, int, string) {}, h.logger)
	if err != nil {
		t.Fatalf("runBulkFlow: %v", err)
	}
	assertStatuses(t, results, bulk.StatusSigned, bulk.StatusFailed, bulk.StatusSigned)
	want := "This YubiKey's key may not sign “Appointment” credentials (allowed: Other), so the credential would not verify."
	if results[1].Err != want || results[1].URL != "" {
		t.Errorf("row 1 = %+v, want Err %q", results[1], want)
	}
	if h.keyReads != 1 || h.pinReads != 1 || h.opens != 2 {
		t.Errorf("keyReads=%d pinReads=%d opens=%d, want 1, 1 and 2", h.keyReads, h.pinReads, h.opens)
	}
	if n := h.logCount(t); n != 2 {
		t.Errorf("log records = %d, want 2", n)
	}
	assertCountsInvariant(t, results)
	data, err := bulkResultsCSV(results)
	if err != nil || !strings.Contains(string(data), want) {
		t.Errorf("results CSV lacks the row's message (%v):\n%s", err, data)
	}
	if !strings.Contains(debugLogText(t, h), "bulk key check: line 3: "+ErrHonorNotAllowed.Error()) {
		t.Errorf("row rejection not logged:\n%s", debugLogText(t, h))
	}
}

// TestBulkFlow_KeyRejectedAfterPINStopsBatch: the pre-check passes every
// row, then the card's key is refused at the first signing open (the card
// was swapped after the PIN), which stops the batch.
func TestBulkFlow_KeyRejectedAfterPINStopsBatch(t *testing.T) {
	h := newBulkHarness(t)
	results := h.plan(t, threeRowCSV)
	preChecks := bulk.Summarize(results).ToSign
	calls := 0
	checkKey := func([32]byte, core.SignRequest) error {
		calls++
		if calls <= preChecks { // the pre-check, one call per to_sign row
			return nil
		}
		return &keyRejectedError{msg: ErrKeyNotRegistered.Error(), reason: ErrKeyNotRegistered}
	}
	err := runBulkFlow(context.Background(), results, h.logPath, h.openAdapter, checkKey,
		h.readPin, nil, func(int, int, string) {}, h.logger)
	if !errors.Is(err, ErrKeyNotRegistered) {
		t.Fatalf("runBulkFlow err = %v, want ErrKeyNotRegistered", err)
	}
	if bulkStop(err) != BulkFailed {
		t.Errorf("stop = %q, want failed", bulkStop(err))
	}
	assertStatuses(t, results, bulk.StatusFailed, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	if h.keyReads != 1 || h.pinReads != 1 || h.opens != 1 {
		t.Errorf("keyReads=%d pinReads=%d opens=%d, want 1, 1 and 1", h.keyReads, h.pinReads, h.opens)
	}
	if n := h.logCount(t); n != 0 {
		t.Errorf("log records = %d, want 0", n)
	}
}

func TestBulkFlow_EveryRowRejectedAsksNoPIN(t *testing.T) {
	h := newBulkHarness(t)
	results := h.plan(t, threeRowCSV)
	connecting := 0
	err := runBulkFlow(context.Background(), results, h.logPath, h.openAdapter, rejectAll, h.readPin,
		func() { connecting++ }, func(int, int, string) {}, h.logger)
	if err != nil {
		t.Fatalf("runBulkFlow: %v", err)
	}
	assertStatuses(t, results, bulk.StatusFailed, bulk.StatusFailed, bulk.StatusFailed)
	if h.keyReads != 1 || h.pinReads != 0 || h.opens != 0 || connecting != 0 {
		t.Errorf("keyReads=%d pinReads=%d opens=%d connecting=%d; want only the key read", h.keyReads, h.pinReads, h.opens, connecting)
	}
	if results[0].Err != ErrKeyNotRegistered.Error() {
		t.Errorf("row 0 Err = %q", results[0].Err)
	}
}

func TestBulkFlow_KeyReadFailureStopsBeforePIN(t *testing.T) {
	h := newBulkHarness(t)
	h.newSigner = func(ed25519.PrivateKey) core.SigningAdapter { return &errorExportAdapter{} }
	results := h.plan(t, threeRowCSV)
	err := h.run(t, context.Background(), results, nil)
	var sfe *signFlowError
	if !errors.As(err, &sfe) || sfe.Phase != phaseExportKey {
		t.Fatalf("err = %v, want an export_key failure", err)
	}
	assertStatuses(t, results, bulk.StatusNotAttempted, bulk.StatusNotAttempted, bulk.StatusNotAttempted)
	if h.pinReads != 0 {
		t.Errorf("pinReads = %d, want 0", h.pinReads)
	}
}

func debugLogText(t *testing.T, h *bulkHarness) string {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(filepath.Dir(h.logPath), "debug.log"))
	return string(data)
}

// --- App ---

// offlineHarness is an appHarness whose registry could not be fetched.
func offlineHarness(t *testing.T) *appHarness {
	t.Helper()
	h := newAppHarness(t, nil)
	h.app.reg, h.app.registryFetched = core.Registry{}, false
	return h
}

func TestSign_OfflineRefusedBeforeAnything(t *testing.T) {
	h := offlineHarness(t)
	_, err := h.app.Sign(context.Background(), validFields("Alice"))
	var se *SignError
	if !errors.As(err, &se) || !errors.Is(err, ErrOffline) {
		t.Fatalf("err = %#v, want a SignError matching ErrOffline", err)
	}
	const want = "Signing is unavailable: the key registry could not be downloaded. Check your internet connection and restart RHG Authenticator."
	if se.Message != want || se.OfferReport || se.ReportID != "" {
		t.Errorf("SignError = %+v", se)
	}
	if h.opens != 0 || h.prompter.callCount() != 0 {
		t.Errorf("offline Sign reached the card (%d) or PIN prompt (%d)", h.opens, h.prompter.callCount())
	}
	if _, statErr := os.Stat(h.app.logPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("issuance log touched: %v", statErr)
	}
	if h.app.lastReport != nil {
		t.Error("offline failure became reportable")
	}
	if names, _ := h.events.snapshot(); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
}

// TestSign_OfflineReturnsAnIssuedCredential: offline, a credential already in
// the issuance log is shown from it (as a bulk run does), with no card access;
// only a new signature is refused.
func TestSign_OfflineReturnsAnIssuedCredential(t *testing.T) {
	h := newAppHarness(t, nil)
	first, err := h.app.Sign(context.Background(), validFields("Alice"))
	if err != nil {
		t.Fatal(err)
	}
	h.app.reg, h.app.registryFetched = core.Registry{}, false
	opens, prompts := h.opens, h.prompter.callCount()
	again, err := h.app.Sign(context.Background(), validFields("Alice"))
	if err != nil || !again.Existing || again.URL != first.URL {
		t.Fatalf("offline Sign of a logged credential = %+v, %v; want it Existing", again, err)
	}
	if h.opens != opens || h.prompter.callCount() != prompts {
		t.Error("offline Sign reached the card or PIN prompt")
	}
	if _, err := h.app.Sign(context.Background(), validFields("Bob")); !errors.Is(err, ErrOffline) {
		t.Errorf("offline Sign of a new credential: err = %v, want ErrOffline", err)
	}
}

// TestBulk_OfflineNothingToSignCompletes: a plan with no rows to sign (here
// only invalid ones) runs offline, so its results can still be exported.
func TestBulk_OfflineNothingToSignCompletes(t *testing.T) {
	h := offlineHarness(t)
	plan, err := h.app.LoadBulk(writeCSV(t, h.dir, "name,honor,detail,date\nBob,Bogus,x,2026-01-02\n"))
	if err != nil || plan.ToSign != 0 {
		t.Fatalf("LoadBulk offline = %+v, %v; want a plan with nothing to sign", plan, err)
	}
	out, err := h.app.RunBulk(context.Background())
	if err != nil || out.Stopped != BulkCompleted {
		t.Fatalf("RunBulk = %+v, %v; want completed", out, err)
	}
	if h.opens != 0 || h.prompter.callCount() != 0 {
		t.Errorf("RunBulk reached the card (%d) or PIN prompt (%d)", h.opens, h.prompter.callCount())
	}
	if err := h.app.ExportBulkResults(filepath.Join(t.TempDir(), "results.csv")); err != nil {
		t.Errorf("ExportBulkResults: %v", err)
	}
}

func TestBulk_OfflineLoadWorksRunRefused(t *testing.T) {
	h := offlineHarness(t)
	plan, err := h.app.LoadBulk(writeCSV(t, h.dir, threeRowCSV))
	if err != nil || plan.ToSign != 3 {
		t.Fatalf("LoadBulk offline = %+v, %v; want the plan", plan, err)
	}
	out, err := h.app.RunBulk(context.Background())
	if err != ErrOffline || !reflect.DeepEqual(out, BulkOutcome{}) {
		t.Fatalf("RunBulk = %+v, %v; want ErrOffline", out, err)
	}
	if h.opens != 0 || h.prompter.callCount() != 0 {
		t.Errorf("offline RunBulk reached the card (%d) or PIN prompt (%d)", h.opens, h.prompter.callCount())
	}
	if _, statErr := os.Stat(h.app.logPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("issuance log touched: %v", statErr)
	}
	h.app.mu.Lock()
	rows := statuses(h.app.plan)
	h.app.mu.Unlock()
	if strings.Join(rows, ",") != "to_sign,to_sign,to_sign" {
		t.Errorf("plan rows = %v, want untouched", rows)
	}
	if names, _ := h.events.snapshot(); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
}

func TestSign_KeyRejectedBeforePIN(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entry  func(priv ed25519.PrivateKey) core.KeyEntry
		reason error
		msg    string
	}{
		{"not registered", func(ed25519.PrivateKey) core.KeyEntry {
			_, other, _ := ed25519.GenerateKey(nil)
			return keyEntry(other, "", "")
		}, ErrKeyNotRegistered, ErrKeyNotRegistered.Error()},
		{"expired for the date", func(p ed25519.PrivateKey) core.KeyEntry { return keyEntry(p, "2026-03-13", "") }, ErrKeyExpired, msgExpiredBefore},
		{"honor not allowed", func(p ed25519.PrivateKey) core.KeyEntry { return keyEntry(p, "", `["Appointment"]`) }, ErrHonorNotAllowed, msgOtherOnlyAppt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, nil)
			h.app.reg = registryWith(tc.entry(h.priv))
			_, err := h.app.Sign(context.Background(), validFields("Alice"))
			var se *SignError
			if !errors.As(err, &se) || !errors.Is(err, tc.reason) {
				t.Fatalf("err = %#v, want a SignError matching %v", err, tc.reason)
			}
			if se.Message != tc.msg || se.OfferReport || se.ReportID != "" {
				t.Errorf("SignError = %+v, want message %q and no report", se, tc.msg)
			}
			if h.prompter.callCount() != 0 || h.opens != 1 {
				t.Errorf("prompts=%d opens=%d; want no PIN, only the key read", h.prompter.callCount(), h.opens)
			}
			if _, statErr := os.Stat(h.app.logPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("issuance log written: %v", statErr)
			}
		})
	}
}

func TestSign_DateAndBackdatingAccepted(t *testing.T) {
	h := newAppHarness(t, nil)
	e := keyEntry(h.priv, "2026-03-14", "")
	e.From = "2026-12-01" // after the credential date: backdated, still verifies
	h.app.reg = registryWith(e)
	if res, err := h.app.Sign(context.Background(), validFields("Alice")); err != nil || res.URL == "" {
		t.Fatalf("Sign on the key's last day = %+v, %v; want signed", res, err)
	}
}

func TestBulk_RunMixedRowsAndExport(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.reg = registryWith(keyEntry(h.priv, "", `["Other"]`))
	if _, err := h.app.LoadBulk(writeCSV(t, h.dir, threeRowCSV)); err != nil {
		t.Fatal(err)
	}
	out, err := h.app.RunBulk(context.Background())
	if err != nil || out.Stopped != BulkCompleted ||
		out.SummaryLine != "Processed 3 rows: 2 successful (2 newly signed, 0 already issued), 0 invalid, 1 failed/not attempted." {
		t.Fatalf("RunBulk = %+v, %v", out, err)
	}
	// The refused row's reason reaches the outcome, not only the CSV.
	wantFailed := []string{"line 3: This YubiKey's key may not sign “Appointment” credentials (allowed: Other), so the credential would not verify."}
	if !slices.Equal(out.FailedLines, wantFailed) {
		t.Errorf("FailedLines = %q, want %q", out.FailedLines, wantFailed)
	}
	if n := h.prompter.callCount(); n != 1 {
		t.Errorf("PIN prompts = %d, want 1", n)
	}
	path := filepath.Join(t.TempDir(), "r.csv")
	if err := h.app.ExportBulkResults(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "may not sign “Appointment” credentials (allowed: Other)") {
		t.Errorf("results CSV lacks the rejection:\n%s", data)
	}
	recs, err := issuancelog.ReadLog(h.app.logPath)
	if err != nil || len(recs) != 2 {
		t.Errorf("issuance log = %d records, %v; want 2", len(recs), err)
	}
	for _, r := range recs {
		if r.Honor != "Other" {
			t.Errorf("logged a %q credential", r.Honor)
		}
	}
}
