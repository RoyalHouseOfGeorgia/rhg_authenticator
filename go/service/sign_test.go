package service

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// mockSignAdapter mirrors core/sign_test.go's mockAdapter.
// Intentionally duplicated to keep test packages independent.
type mockSignAdapter struct {
	secretKey ed25519.PrivateKey
}

func (m *mockSignAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], m.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (m *mockSignAdapter) SignBytes(data []byte) ([]byte, error) {
	return ed25519.Sign(m.secretKey, data), nil
}

// errorExportAdapter returns an error on ExportPublicKey.
type errorExportAdapter struct{}

func (e *errorExportAdapter) ExportPublicKey() ([32]byte, error) {
	return [32]byte{}, fmt.Errorf("hardware failure")
}

func (e *errorExportAdapter) SignBytes(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not called")
}

// errorSignAdapter has a valid ExportPublicKey but fails on SignBytes.
type errorSignAdapter struct {
	secretKey ed25519.PrivateKey
}

func (e *errorSignAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], e.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (e *errorSignAdapter) SignBytes(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("signing hardware fault")
}

// nopCloser wraps io.NopCloser for adapter closers.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func dummyReadPin() (string, error) { return "123456", nil }

// acceptAnyKey is a keyChecker for tests of the rest of the flow; the key
// check itself is tested with checkSigningKey.
func acceptAnyKey([32]byte, core.SignRequest) error { return nil }

// TestExecuteSignFlow_PreResolvedPINThreadedToOpen proves the fix's core wiring:
// the PIN resolved up-front is the value handed to openAdapter's readPin closure
// (i.e. what piv-go's PINPrompt would receive), so the transaction is never held
// across human PIN entry.
func TestExecuteSignFlow_PreResolvedPINThreadedToOpen(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

	readPin := func() (string, error) { return "998877", nil }

	var pinSeenByOpen string
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		pinSeenByOpen, _ = rp()
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}

	if _, err := executeSignFlow(req, filepath.Join(tmpDir, "issuance.log"), true, openAdapter, acceptAnyKey, readPin, nil, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pinSeenByOpen != "998877" {
		t.Errorf("openAdapter's readPin returned %q, want the pre-resolved PIN %q", pinSeenByOpen, "998877")
	}
}

// countingOpener returns an adapterOpener for adapter that counts the
// PIN-free key reads (its readPin yields "") and the signing opens (its
// readPin yields the pre-resolved PIN).
func countingOpener(adapter core.SigningAdapter, keyReads, signOpens *int) adapterOpener {
	return func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		if pin, _ := rp(); pin == "" {
			*keyReads++
		} else {
			*signOpens++
		}
		return adapter, nopCloser{}, nil
	}
}

// TestExecuteSignFlow_PromptsBeforeOpen pins the ordering: a PIN-free key
// read (closed again) and key check → readPin → onConnecting → the signing openAdapter.
func TestExecuteSignFlow_PromptsBeforeOpen(t *testing.T) {
	var order []string
	readPin := func() (string, error) { order = append(order, "readPin"); return "123456", nil }
	onConnecting := func() { order = append(order, "onConnecting") }

	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		if pin, _ := rp(); pin == "" {
			order = append(order, "keyRead")
		} else {
			order = append(order, "openAdapter")
		}
		return adapter, closeFunc(func() { order = append(order, "close") }), nil
	}
	checkKey := func([32]byte, core.SignRequest) error { order = append(order, "checkKey"); return nil }

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}
	if _, err := executeSignFlow(req, filepath.Join(tmpDir, "issuance.log"), true, openAdapter, checkKey, readPin, onConnecting, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The key-read handle is closed before the PIN prompt: piv-go holds an
	// exclusive PC/SC transaction while a card is open.
	const want = "keyRead,close,checkKey,readPin,onConnecting,openAdapter,checkKey,close"
	if got := strings.Join(order, ","); got != want {
		t.Errorf("call order = %q, want %s", got, want)
	}
}

// TestExecuteSignFlow_ReadPINErrorShortCircuits verifies a readPin failure is
// surfaced before the signing Open and before onConnecting fires; only the
// PIN-free key read opened the card.
func TestExecuteSignFlow_ReadPINErrorShortCircuits(t *testing.T) {
	sentinel := errors.New("pin dialog boom")
	readPin := func() (string, error) { return "", sentinel }
	var keyReads, signOpens int
	onConnectingCalled := false
	_, priv, _ := ed25519.GenerateKey(nil)
	openAdapter := countingOpener(&mockSignAdapter{secretKey: priv}, &keyReads, &signOpens)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}
	_, err := executeSignFlow(req, tempLogPath(t), true, openAdapter, acceptAnyKey, readPin, func() { onConnectingCalled = true }, logger)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected readPin error, got %v", err)
	}
	if keyReads != 1 || signOpens != 0 {
		t.Errorf("keyReads=%d signOpens=%d, want 1 and 0", keyReads, signOpens)
	}
	if onConnectingCalled {
		t.Error("onConnecting must not be called after a readPin error")
	}
}

// TestExecuteSignFlow_PINSentinelsSurviveAndClassify pins the load-bearing
// invariant behind the prompt-before-open reorder: a PIN sentinel returned from
// readPin survives executeSignFlow with errors.Is intact, openAdapter is never
// called with readPin (so piv-go can never %v-wrap the sentinel; the key read
// before the prompt gets a no-op), and signFlowErrorMessage classifies it
// correctly rather than as a hardware error. A regression to lazy PINPrompt
// (passing readPin into openAdapter) would break errors.Is or the open count,
// failing this test in CI.
func TestExecuteSignFlow_PINSentinelsSurviveAndClassify(t *testing.T) {
	cases := []struct {
		name        string
		readPinErr  error
		base        error  // sentinel that errors.Is must still match afterwards
		wantMsgPart string // substring of signFlowErrorMessage output ("" = not checked: Sign and bulk handle a cancel before mapping it)
	}{
		{"cancelled", errSigningCancelled, errSigningCancelled, ""},
		{"timed out", errPINEntryTimedOut, errPINEntryTimedOut, "timed out"},
		{"cache unavailable", fmt.Errorf("%w: mlock failed", errPINCacheUnavailable), errPINCacheUnavailable, "secure the PIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var keyReads, signOpens int
			_, priv, _ := ed25519.GenerateKey(nil)
			openAdapter := countingOpener(&mockSignAdapter{secretKey: priv}, &keyReads, &signOpens)
			readPin := func() (string, error) { return "", tc.readPinErr }
			tmpDir := t.TempDir()
			logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
			req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}

			_, err := executeSignFlow(req, tempLogPath(t), true, openAdapter, acceptAnyKey, readPin, nil, logger)

			if !errors.Is(err, tc.base) {
				t.Errorf("sentinel lost through executeSignFlow: errors.Is(%v, %v) = false", err, tc.base)
			}
			if keyReads != 1 || signOpens != 0 {
				t.Errorf("keyReads=%d signOpens=%d, want 1 and 0: the signing open must not follow a readPin error", keyReads, signOpens)
			}
			if got := signFlowErrorMessage(err); tc.wantMsgPart != "" && !strings.Contains(got, tc.wantMsgPart) {
				t.Errorf("signFlowErrorMessage = %q, want substring %q", got, tc.wantMsgPart)
			}
		})
	}
}

// TestExecuteSignFlow_AdapterOpenError: the key read and the PIN succeed,
// then the signing open fails (card pulled after the PIN); the open error is
// returned unwrapped.
func TestExecuteSignFlow_AdapterOpenError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	openErr := fmt.Errorf("pcsc daemon not running")
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		if pin, _ := rp(); pin == "" {
			return &mockSignAdapter{secretKey: priv}, nopCloser{}, nil // the key read
		}
		return nil, nil, openErr
	}
	pins := 0
	readPin := func() (string, error) { pins++; return "123456", nil }
	_, err := executeSignFlow(inputReq("Distinguished service"), tempLogPath(t), true, openAdapter, acceptAnyKey, readPin, nil, nil)
	if err != openErr {
		t.Errorf("err = %v, want the open error unwrapped", err)
	}
	if pins != 1 {
		t.Errorf("readPin calls = %d, want 1", pins)
	}
}

func TestExecuteSignFlow_SignError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &errorSignAdapter{secretKey: priv}
	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuance.log")

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	_, err := executeSignFlow(req, logPath, true, openAdapter, acceptAnyKey, dummyReadPin, nil, logger)
	if err == nil {
		t.Fatal("expected error from SignBytes")
	}
	var sfe *signFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *signFlowError, got %T", err)
	}
	if sfe.Phase != phaseSign {
		t.Errorf("Phase = %q, want %q", sfe.Phase, phaseSign)
	}
}

func TestExecuteSignFlow_LogWriteFailureNonFatal(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))

	// Use a log path in a non-existent directory to force a write error.
	logPath := filepath.Join(tmpDir, "nonexistent", "subdir", "issuances.json")

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	// Should succeed — log failure is non-fatal.
	result, err := executeSignFlow(req, logPath, true, openAdapter, acceptAnyKey, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("expected no error (log failure is non-fatal), got: %v", err)
	}
	if result.Response.URL == "" {
		t.Error("expected non-empty URL despite log failure")
	}

	// Verify the debug log captured the failure.
	debugData, err := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if err != nil {
		t.Fatalf("ReadFile debug.log error: %v", err)
	}
	if !strings.Contains(string(debugData), "log append failed") {
		t.Errorf("debug log should contain 'log append failed', got: %s", string(debugData))
	}
}

// seedEnabledCache returns an enabled PinCache primed with a PIN, asserting the
// PIN is retrievable before the caller exercises clearPINCacheOnAuthError. Set
// silently no-ops on a disabled cache, so seeding via SetEnabled(true) and
// verifying Get() up front prevents a vacuously-passing post-clear assertion.
func seedEnabledCache(t *testing.T) *yubikey.PinCache {
	t.Helper()
	cache := yubikey.NewPinCache()
	t.Cleanup(cache.Close)
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}
	if _, ok := cache.Get(); !ok {
		t.Fatal("cache should hold a PIN before clear")
	}
	return cache
}

func TestClearPINCacheOnAuthError(t *testing.T) {
	cases := []struct {
		name    string
		seeded  bool    // an enabled cache holding a PIN; otherwise a disabled, empty cache
		errs    []error // applied in order, checking the cache after each
		wantPIN bool
	}{
		{
			name:   "sign flow error clears",
			seeded: true,
			errs:   []error{&signFlowError{Phase: phaseSign, Err: fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 2})}},
		},
		{
			name:    "non-auth PCSC error preserves",
			seeded:  true,
			errs:    []error{errors.New("connecting to smart card: the smart card has been removed")},
			wantPIN: true,
		},
		{
			// clearLocked nil-guards, so neither call panics on an empty cache.
			name: "nil and auth error on empty cache",
			errs: []error{nil, &signFlowError{Phase: phaseSign, Err: piv.AuthErr{}}},
		},
		{
			name:   "bare unwrapped AuthErr clears",
			seeded: true,
			errs:   []error{piv.AuthErr{}},
		},
		{
			// The exact shape piv-go produces: a VERIFY failure wrapped "verify pin:
			// %w", re-wrapped by the adapter, boxed in a signFlowError. If a piv-go
			// bump changes that %w to %v, errors.As breaks and this fails before a
			// wrong PIN can be replayed into the PIV retry counter (a signing-key
			// lockout).
			name:   "realistic verify pin chain clears",
			seeded: true,
			errs: []error{&signFlowError{
				Phase: phaseSign,
				Err:   fmt.Errorf("signing failed: %w", fmt.Errorf("verify pin: %w", piv.AuthErr{Retries: 2})),
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cache *yubikey.PinCache
			if tc.seeded {
				cache = seedEnabledCache(t)
			} else {
				cache = yubikey.NewPinCache()
				t.Cleanup(cache.Close)
			}
			for _, err := range tc.errs {
				clearPINCacheOnAuthError(err, cache)
				if _, ok := cache.Get(); ok != tc.wantPIN {
					t.Errorf("after %v: cache holds PIN = %v, want %v", err, ok, tc.wantPIN)
				}
			}
		})
	}
}

func TestSignFlowError_ErrorString(t *testing.T) {
	sfe := &signFlowError{Phase: phaseQR, Err: fmt.Errorf("encode failed")}
	want := "qr: encode failed"
	if got := sfe.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// closeFunc is an io.Closer that calls itself.
type closeFunc func()

func (f closeFunc) Close() error { f(); return nil }

// countingCloser records how many times Close is called.
type countingCloser struct{ n int }

func (c *countingCloser) Close() error { c.n++; return nil }

func validSignRequest() core.SignRequest {
	return core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}
}

func TestSignAndLog_Success(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	closer := &countingCloser{}
	var pinSeen string
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		pinSeen, _ = rp()
		return &mockSignAdapter{secretKey: priv}, closer, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	// NFD input: e + combining acute accent.
	req := core.SignRequest{
		Recipient: "Café",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "résumé",
		Date:      "2026-03-14",
	}

	resp, err := signAndLog(req, logPath, openAdapter, acceptAnyKey, "112233", logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.URL == "" || resp.Signature == "" || resp.PayloadSHA256 == "" {
		t.Errorf("incomplete response: %+v", resp)
	}
	if pinSeen != "112233" {
		t.Errorf("openAdapter readPin returned %q, want %q", pinSeen, "112233")
	}
	if closer.n != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.n)
	}

	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.Recipient != "Café" {
		t.Errorf("Recipient = %q, want NFC %q", r.Recipient, "Café")
	}
	if r.Detail != "résumé" {
		t.Errorf("Detail = %q, want NFC %q", r.Detail, "résumé")
	}
	if r.Honor != req.Honor || r.Date != req.Date {
		t.Errorf("Honor/Date = %q/%q, want %q/%q", r.Honor, r.Date, req.Honor, req.Date)
	}
	if r.PayloadSHA256 != resp.PayloadSHA256 {
		t.Errorf("PayloadSHA256 = %q, want %q", r.PayloadSHA256, resp.PayloadSHA256)
	}
	if r.SignatureB64URL != resp.Signature {
		t.Errorf("SignatureB64URL = %q, want %q", r.SignatureB64URL, resp.Signature)
	}
	if r.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestSignAndLog_LogAppendFailureReturnsResponseAndPhaseLog(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	closer := &countingCloser{}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &mockSignAdapter{secretKey: priv}, closer, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	// ReadLog treats a missing file as empty; AppendRecord's temp-file write
	// then fails on every OS because the parent directory does not exist.
	logPath := filepath.Join(tmpDir, "missing", "log.json")

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, acceptAnyKey, "123456", logger)
	if resp.URL == "" || resp.Signature == "" || resp.PayloadSHA256 == "" {
		t.Errorf("expected a valid response despite log failure, got %+v", resp)
	}
	if !errors.Is(err, core.ErrNotLogged) {
		t.Fatalf("errors.Is(err, ErrNotLogged) = false; err = %v", err)
	}
	var sfe *signFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *signFlowError, got %T", err)
	}
	if sfe.Phase != phaseLog {
		t.Errorf("Phase = %q, want %q", sfe.Phase, phaseLog)
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("underlying *fs.PathError missing from chain: %v", err)
	}
	if closer.n != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.n)
	}

	debugData, readErr := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if readErr != nil {
		t.Fatalf("ReadFile debug.log: %v", readErr)
	}
	if !strings.Contains(string(debugData), "log append failed") {
		t.Errorf("debug log should contain 'log append failed', got: %s", debugData)
	}
}

func TestSignAndLog_ExportKeyError(t *testing.T) {
	closer := &countingCloser{}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &errorExportAdapter{}, closer, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, acceptAnyKey, "123456", logger)
	var sfe *signFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *signFlowError, got %T (%v)", err, err)
	}
	if sfe.Phase != phaseExportKey {
		t.Errorf("Phase = %q, want %q", sfe.Phase, phaseExportKey)
	}
	if resp.URL != "" {
		t.Errorf("expected zero response, got %+v", resp)
	}
	if closer.n != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.n)
	}
	if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
		t.Errorf("no log record should be written on export failure, stat: %v", statErr)
	}
}

func TestSignAndLog_SignError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	closer := &countingCloser{}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &errorSignAdapter{secretKey: priv}, closer, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, acceptAnyKey, "123456", logger)
	var sfe *signFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *signFlowError, got %T (%v)", err, err)
	}
	if sfe.Phase != phaseSign {
		t.Errorf("Phase = %q, want %q", sfe.Phase, phaseSign)
	}
	if resp.URL != "" {
		t.Errorf("expected zero response, got %+v", resp)
	}
	if closer.n != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.n)
	}
	if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
		t.Errorf("no log record should be written on sign failure, stat: %v", statErr)
	}
}

func TestSignAndLog_OpenError(t *testing.T) {
	openErr := errors.New("pcsc daemon not running")
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return nil, nil, openErr
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	_, err := signAndLog(validSignRequest(), logPath, openAdapter, acceptAnyKey, "123456", logger)
	if err != openErr {
		t.Errorf("expected the unwrapped open error, got %v", err)
	}
	var sfe *signFlowError
	if errors.As(err, &sfe) {
		t.Errorf("open error must not be wrapped in signFlowError, got phase %q", sfe.Phase)
	}
	if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
		t.Errorf("log file should not exist after open failure, stat: %v", statErr)
	}
	debugData, readErr := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if readErr != nil {
		t.Fatalf("ReadFile debug.log: %v", readErr)
	}
	if !strings.Contains(string(debugData), "connect: pcsc daemon not running") {
		t.Errorf("debug log should contain connect error, got: %s", debugData)
	}
}

// countingStubs returns a readPin that counts its calls and a countingOpener
// whose adapter signs with priv.
func countingStubs(priv ed25519.PrivateKey) (readPin func() (string, error), openAdapter adapterOpener, pinCalls, keyReads, signOpens *int) {
	pinCalls, keyReads, signOpens = new(int), new(int), new(int)
	readPin = func() (string, error) { *pinCalls++; return "123456", nil }
	return readPin, countingOpener(&mockSignAdapter{secretKey: priv}, keyReads, signOpens), pinCalls, keyReads, signOpens
}

func TestExecuteSignFlow_ExistingIssuanceSkipsSigning(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")
	req := validSignRequest()

	// Seed the log via the real sign path.
	seedOpen := func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &mockSignAdapter{secretKey: priv}, nopCloser{}, nil
	}
	orig, err := signAndLog(req, logPath, seedOpen, acceptAnyKey, "123456", logger)
	if err != nil {
		t.Fatalf("seed signAndLog: %v", err)
	}

	readPin, openAdapter, pinCalls, keyReads, signOpens := countingStubs(priv)
	connecting := 0
	result, err := executeSignFlow(req, logPath, true, openAdapter, acceptAnyKey, readPin, func() { connecting++ }, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *pinCalls != 0 || *keyReads != 0 || *signOpens != 0 || connecting != 0 {
		t.Errorf("readPin/keyReads/signOpens/onConnecting = %d/%d/%d/%d, want all 0", *pinCalls, *keyReads, *signOpens, connecting)
	}
	if !result.Existing {
		t.Error("Existing = false, want true")
	}
	if result.Response != orig {
		t.Errorf("Response = %+v, want %+v", result.Response, orig)
	}
	if len(result.PNGPreview) == 0 {
		t.Error("expected non-empty PNGPreview")
	}
	if result.Hash8 != orig.PayloadSHA256[:8] {
		t.Errorf("Hash8 = %q, want %q", result.Hash8, orig.PayloadSHA256[:8])
	}

	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("log has %d records, want 1", len(records))
	}
}

func TestExecuteSignFlow_NoMatchSignsAndAppends(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	// Seed a different issuance so the log is non-empty but has no match.
	other := validSignRequest()
	other.Recipient = "Jane Roe"
	seedOpen := func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &mockSignAdapter{secretKey: priv}, nopCloser{}, nil
	}
	if _, err := signAndLog(other, logPath, seedOpen, acceptAnyKey, "123456", logger); err != nil {
		t.Fatalf("seed signAndLog: %v", err)
	}

	readPin, openAdapter, pinCalls, keyReads, signOpens := countingStubs(priv)
	result, err := executeSignFlow(validSignRequest(), logPath, true, openAdapter, acceptAnyKey, readPin, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *pinCalls != 1 || *keyReads != 1 || *signOpens != 1 {
		t.Errorf("readPin/keyReads/signOpens = %d/%d/%d, want 1/1/1", *pinCalls, *keyReads, *signOpens)
	}
	if result.Existing {
		t.Error("Existing = true, want false")
	}

	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("log has %d records, want 2", len(records))
	}
}

func TestExecuteSignFlow_UnreadableLogBlocksSigning(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	debugPath := filepath.Join(tmpDir, "debug.log")
	logger := debuglog.New(debugPath)
	logPath := filepath.Join(tmpDir, "issuances.json")
	if err := os.WriteFile(logPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	readPin, openAdapter, pinCalls, keyReads, signOpens := countingStubs(priv)
	_, err := executeSignFlow(validSignRequest(), logPath, true, openAdapter, acceptAnyKey, readPin, nil, logger)
	if !errors.Is(err, errIssuanceLogUnreadable) {
		t.Fatalf("err = %v, want errIssuanceLogUnreadable", err)
	}
	if *pinCalls != 0 || *keyReads != 0 || *signOpens != 0 {
		t.Errorf("readPin/keyReads/signOpens = %d/%d/%d, want all 0", *pinCalls, *keyReads, *signOpens)
	}
	data, rerr := os.ReadFile(debugPath)
	if rerr != nil {
		t.Fatalf("debug log not written: %v", rerr)
	}
	if !strings.Contains(string(data), "pre-sign check") {
		t.Errorf("debug log should record the pre-sign check failure, got: %q", data)
	}
}

func TestExecuteSignFlow_MalformedStoredSignatureIsResigned(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")
	req := validSignRequest()

	payload, err := core.BuildPayload(req)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	rec := issuancelog.IssuanceRecord{
		Timestamp:       "2026-03-14T00:00:00Z",
		Recipient:       req.Recipient,
		Honor:           req.Honor,
		Detail:          req.Detail,
		Date:            req.Date,
		PayloadSHA256:   core.PayloadSHA256Hex(payload),
		SignatureB64URL: core.Encode(make([]byte, 32)), // valid base64url, wrong length
	}
	if err := issuancelog.AppendRecord(logPath, rec); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	readPin, openAdapter, pinCalls, keyReads, signOpens := countingStubs(priv)
	result, err := executeSignFlow(req, logPath, true, openAdapter, acceptAnyKey, readPin, nil, logger)
	if err != nil {
		t.Fatalf("executeSignFlow: %v", err)
	}
	if result.Existing {
		t.Error("Existing = true, want false (malformed signature must not be reused)")
	}
	if *pinCalls != 1 || *keyReads != 1 || *signOpens != 1 {
		t.Errorf("readPin/keyReads/signOpens = %d/%d/%d, want 1/1/1", *pinCalls, *keyReads, *signOpens)
	}
	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("log has %d records, want 2 (malformed kept + fresh appended)", len(records))
	}
	if got := records[1].SignatureB64URL; got != result.Response.Signature || got == rec.SignatureB64URL {
		t.Errorf("appended signature = %q, want the fresh signature %q", got, result.Response.Signature)
	}
}

// tempLogPath returns an issuance log path in a fresh temp dir.
func tempLogPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "issuances.json")
}
