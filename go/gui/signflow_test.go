package gui

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

	if _, err := executeSignFlow(req, filepath.Join(tmpDir, "issuance.log"), openAdapter, readPin, nil, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pinSeenByOpen != "998877" {
		t.Errorf("openAdapter's readPin returned %q, want the pre-resolved PIN %q", pinSeenByOpen, "998877")
	}
}

// TestExecuteSignFlow_PromptsBeforeOpen pins the ordering: readPin → onConnecting
// → openAdapter.
func TestExecuteSignFlow_PromptsBeforeOpen(t *testing.T) {
	var order []string
	readPin := func() (string, error) { order = append(order, "readPin"); return "123456", nil }
	onConnecting := func() { order = append(order, "onConnecting") }

	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		order = append(order, "openAdapter")
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}
	if _, err := executeSignFlow(req, filepath.Join(tmpDir, "issuance.log"), openAdapter, readPin, onConnecting, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.Join(order, ","); got != "readPin,onConnecting,openAdapter" {
		t.Errorf("call order = %q, want readPin,onConnecting,openAdapter", got)
	}
}

// TestExecuteSignFlow_ReadPINErrorShortCircuits verifies a readPin failure is
// surfaced before any card Open and before onConnecting fires.
func TestExecuteSignFlow_ReadPINErrorShortCircuits(t *testing.T) {
	sentinel := errors.New("pin dialog boom")
	readPin := func() (string, error) { return "", sentinel }
	openCalled := false
	onConnectingCalled := false
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		openCalled = true
		return nil, nil, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}
	_, err := executeSignFlow(req, "", openAdapter, readPin, func() { onConnectingCalled = true }, logger)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected readPin error, got %v", err)
	}
	if openCalled {
		t.Error("openAdapter must not be called after a readPin error")
	}
	if onConnectingCalled {
		t.Error("onConnecting must not be called after a readPin error")
	}
}

// TestExecuteSignFlow_PINSentinelsSurviveAndClassify pins the load-bearing
// invariant behind the prompt-before-open reorder: a PIN sentinel returned from
// readPin survives executeSignFlow with errors.Is intact, openAdapter is never
// called (so piv-go can never %v-wrap the sentinel), and signFlowErrorMessage
// classifies it correctly rather than as a hardware error. A regression to lazy
// PINPrompt (passing readPin into openAdapter) would set openCalled and/or break
// errors.Is, failing this test in CI.
func TestExecuteSignFlow_PINSentinelsSurviveAndClassify(t *testing.T) {
	cases := []struct {
		name        string
		readPinErr  error
		base        error  // sentinel that errors.Is must still match afterwards
		wantMsgPart string // substring of signFlowErrorMessage output ("" = exactly "")
	}{
		{"cancelled", ErrSigningCancelled, ErrSigningCancelled, ""},
		{"timed out", ErrPINEntryTimedOut, ErrPINEntryTimedOut, "timed out"},
		{"cache unavailable", fmt.Errorf("%w: mlock failed", ErrPINCacheUnavailable), ErrPINCacheUnavailable, "secure the PIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			openCalled := false
			openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
				openCalled = true
				return nil, nil, nil
			}
			readPin := func() (string, error) { return "", tc.readPinErr }
			tmpDir := t.TempDir()
			logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
			req := core.SignRequest{Recipient: "A", Honor: "Order of the Crown of Georgia", Detail: "x", Date: "2026-03-14"}

			_, err := executeSignFlow(req, "", openAdapter, readPin, nil, logger)

			if !errors.Is(err, tc.base) {
				t.Errorf("sentinel lost through executeSignFlow: errors.Is(%v, %v) = false", err, tc.base)
			}
			if openCalled {
				t.Error("openAdapter must not be called after a readPin error (keeps piv-go from value-wrapping the sentinel)")
			}
			got := signFlowErrorMessage(err, logger)
			if tc.wantMsgPart == "" {
				if got != "" {
					t.Errorf("signFlowErrorMessage = %q, want empty", got)
				}
			} else if !strings.Contains(got, tc.wantMsgPart) {
				t.Errorf("signFlowErrorMessage = %q, want substring %q", got, tc.wantMsgPart)
			}
		})
	}
}

func TestExecuteSignFlow_HappyPath(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

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

	result, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.PNGPreview) == 0 {
		t.Error("expected non-empty PNGPreview")
	}
	if len(result.Hash8) != 8 {
		t.Errorf("Hash8 length = %d, want 8", len(result.Hash8))
	}
	if result.Response.URL == "" {
		t.Error("expected non-empty URL in response")
	}
	if result.Response.Signature == "" {
		t.Error("expected non-empty Signature in response")
	}
	if result.Response.Payload == "" {
		t.Error("expected non-empty Payload in response")
	}
	if result.Response.PayloadSHA256 == "" {
		t.Error("expected non-empty PayloadSHA256 in response")
	}
}

func TestExecuteSignFlow_AdapterOpenError(t *testing.T) {
	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return nil, nil, fmt.Errorf("pcsc daemon not running")
	}

	_, err := executeSignFlow(core.SignRequest{}, "", openAdapter, dummyReadPin, nil, nil)
	if err == nil {
		t.Fatal("expected error from adapter open")
	}
	if err.Error() != "pcsc daemon not running" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecuteSignFlow_ExportKeyError(t *testing.T) {
	adapter := &errorExportAdapter{}
	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))

	_, err := executeSignFlow(core.SignRequest{}, "", openAdapter, dummyReadPin, nil, logger)
	if err == nil {
		t.Fatal("expected error from ExportPublicKey")
	}
	var sfe *SignFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *SignFlowError, got %T", err)
	}
	if sfe.Phase != PhaseExportKey {
		t.Errorf("Phase = %q, want %q", sfe.Phase, PhaseExportKey)
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

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, nil, logger)
	if err == nil {
		t.Fatal("expected error from SignBytes")
	}
	var sfe *SignFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *SignFlowError, got %T", err)
	}
	if sfe.Phase != PhaseSign {
		t.Errorf("Phase = %q, want %q", sfe.Phase, PhaseSign)
	}
}

func TestExecuteSignFlow_LogFileWritten(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the log file was written by signflow (not by HandleSign).
	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 log record, got %d", len(records))
	}
	if records[0].Recipient != "John Doe" {
		t.Errorf("Recipient = %q, want %q", records[0].Recipient, "John Doe")
	}
	if records[0].Honor != "Order of the Crown of Georgia" {
		t.Errorf("Honor = %q, want %q", records[0].Honor, "Order of the Crown of Georgia")
	}
	if records[0].PayloadSHA256 == "" {
		t.Error("PayloadSHA256 should not be empty")
	}
	if records[0].SignatureB64URL == "" {
		t.Error("SignatureB64URL should not be empty")
	}
	if records[0].Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestExecuteSignFlow_RecordFieldsNFCNormalized(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "issuances.json")

	// NFD input: e + combining acute accent.
	req := core.SignRequest{
		Recipient: "Caf\u0065\u0301",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "re\u0301sume\u0301",
		Date:      "2026-03-14",
	}

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		t.Fatalf("ReadLog error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// Record fields should be NFC-normalized.
	if records[0].Recipient != "Caf\u00e9" {
		t.Errorf("Recipient = %q, want NFC-normalized %q", records[0].Recipient, "Caf\u00e9")
	}
	if records[0].Detail != "r\u00e9sum\u00e9" {
		t.Errorf("Detail = %q, want NFC-normalized %q", records[0].Detail, "r\u00e9sum\u00e9")
	}
	if records[0].Date != "2026-03-14" {
		t.Errorf("Date = %q, want %q", records[0].Date, "2026-03-14")
	}
}

func TestExecuteSignFlow_NoLogWhenPathEmpty(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	// Pass empty logPath — no log file should be created.
	_, err := executeSignFlow(req, "", openAdapter, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no log file was created in the temp directory.
	logPath := filepath.Join(tmpDir, "issuances.json")
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("log file should not exist when logPath is empty, got stat result: %v", err)
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
	result, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, nil, logger)
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
	cache.SetEnabled(true)
	if err := cache.Set("123456"); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}
	if _, ok := cache.Get(); !ok {
		t.Fatal("cache should hold a PIN before clear")
	}
	return cache
}

func TestClearPINCacheOnAuthError_SignFlowErrorClears(t *testing.T) {
	cache := seedEnabledCache(t)

	err := &SignFlowError{
		Phase: PhaseSign,
		Err:   fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 2}),
	}
	clearPINCacheOnAuthError(err, cache)

	if _, ok := cache.Get(); ok {
		t.Error("expected cache to be cleared after auth error")
	}
}

func TestClearPINCacheOnAuthError_NonAuthErrorPreserves(t *testing.T) {
	cache := seedEnabledCache(t)

	// PCSC / "no card" style error — not a PIN authentication failure.
	err := errors.New("connecting to smart card: the smart card has been removed")
	clearPINCacheOnAuthError(err, cache)

	if _, ok := cache.Get(); !ok {
		t.Error("expected cached PIN to survive a non-auth error")
	}
}

func TestClearPINCacheOnAuthError_NilAndAuthOnEmptyCache(t *testing.T) {
	// Empty (disabled) cache: nil error must not panic or clear.
	cache := yubikey.NewPinCache()
	clearPINCacheOnAuthError(nil, cache)
	if _, ok := cache.Get(); ok {
		t.Error("disabled cache should never report a PIN")
	}

	// Auth error against an empty cache: clearLocked nil-guards, so no panic.
	authErr := &SignFlowError{Phase: PhaseSign, Err: piv.AuthErr{}}
	clearPINCacheOnAuthError(authErr, cache)
	if _, ok := cache.Get(); ok {
		t.Error("disabled cache should never report a PIN")
	}
}

func TestClearPINCacheOnAuthError_BareAuthErrClears(t *testing.T) {
	cache := seedEnabledCache(t)

	// Bare, unwrapped piv.AuthErr — no SignFlowError, no %w chain.
	clearPINCacheOnAuthError(piv.AuthErr{}, cache)

	if _, ok := cache.Get(); ok {
		t.Error("expected cache to be cleared for a bare AuthErr")
	}
}

// TestClearPINCacheOnAuthError_RealisticVerifyPinChain pins the lockout-prevention
// invariant against the exact error shape piv-go produces: a card VERIFY failure
// wrapped "verify pin: %w", re-wrapped by the adapter/HandleSign, then boxed in a
// SignFlowError. If a future piv-go bump changes its %w wrap to %v, errors.As
// breaks and this fails in CI — before a wrong PIN can be silently replayed into
// the PIV retry counter (a signing-key lockout DoS).
func TestClearPINCacheOnAuthError_RealisticVerifyPinChain(t *testing.T) {
	cache := seedEnabledCache(t)

	err := &SignFlowError{
		Phase: PhaseSign,
		Err: fmt.Errorf("signing failed: %w",
			fmt.Errorf("verify pin: %w", piv.AuthErr{Retries: 2})),
	}
	clearPINCacheOnAuthError(err, cache)

	if _, ok := cache.Get(); ok {
		t.Error("expected cache cleared for a realistically-wrapped verify-pin AuthErr")
	}
}

func TestSignFlowError_Unwrap(t *testing.T) {
	inner := fmt.Errorf("hardware fault")
	sfe := &SignFlowError{Phase: PhaseSign, Err: inner}
	if errors.Unwrap(sfe) != inner {
		t.Errorf("Unwrap returned %v, want %v", errors.Unwrap(sfe), inner)
	}
}

func TestSignFlowError_Phase(t *testing.T) {
	inner := fmt.Errorf("timeout")
	sfe := &SignFlowError{Phase: PhaseExportKey, Err: inner}

	var extracted *SignFlowError
	if !errors.As(sfe, &extracted) {
		t.Fatal("errors.As failed")
	}
	if extracted.Phase != PhaseExportKey {
		t.Errorf("Phase = %q, want %q", extracted.Phase, PhaseExportKey)
	}
}

func TestSignFlowError_ErrorString(t *testing.T) {
	sfe := &SignFlowError{Phase: PhaseQR, Err: fmt.Errorf("encode failed")}
	want := "qr: encode failed"
	if got := sfe.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

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

	resp, err := signAndLog(req, logPath, openAdapter, "112233", logger)
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

func TestSignAndLog_EmptyLogPathSkipsAppend(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	closer := &countingCloser{}
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &mockSignAdapter{secretKey: priv}, closer, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))

	resp, err := signAndLog(validSignRequest(), "", openAdapter, "123456", logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.URL == "" {
		t.Error("expected non-empty URL")
	}
	if closer.n != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.n)
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

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, "123456", logger)
	if resp.URL == "" || resp.Signature == "" || resp.PayloadSHA256 == "" {
		t.Errorf("expected a valid response despite log failure, got %+v", resp)
	}
	if !errors.Is(err, core.ErrNotLogged) {
		t.Fatalf("errors.Is(err, ErrNotLogged) = false; err = %v", err)
	}
	var sfe *SignFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *SignFlowError, got %T", err)
	}
	if sfe.Phase != PhaseLog {
		t.Errorf("Phase = %q, want %q", sfe.Phase, PhaseLog)
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

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, "123456", logger)
	var sfe *SignFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *SignFlowError, got %T (%v)", err, err)
	}
	if sfe.Phase != PhaseExportKey {
		t.Errorf("Phase = %q, want %q", sfe.Phase, PhaseExportKey)
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

	resp, err := signAndLog(validSignRequest(), logPath, openAdapter, "123456", logger)
	var sfe *SignFlowError
	if !errors.As(err, &sfe) {
		t.Fatalf("expected *SignFlowError, got %T (%v)", err, err)
	}
	if sfe.Phase != PhaseSign {
		t.Errorf("Phase = %q, want %q", sfe.Phase, PhaseSign)
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

	_, err := signAndLog(validSignRequest(), logPath, openAdapter, "123456", logger)
	if err != openErr {
		t.Errorf("expected the unwrapped open error, got %v", err)
	}
	var sfe *SignFlowError
	if errors.As(err, &sfe) {
		t.Errorf("open error must not be wrapped in SignFlowError, got phase %q", sfe.Phase)
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

// TestExecuteSignFlow_LogPathMissingDirIsNonFatal pins that executeSignFlow
// swallows signAndLog's PhaseLog error: single-sign still returns a full
// result (including the QR PNG) when the audit-log append fails.
func TestExecuteSignFlow_LogPathMissingDirIsNonFatal(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	openAdapter := func(rp func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return &mockSignAdapter{secretKey: priv}, nopCloser{}, nil
	}
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	logPath := filepath.Join(tmpDir, "missing", "log.json")

	result, err := executeSignFlow(validSignRequest(), logPath, openAdapter, dummyReadPin, nil, logger)
	if err != nil {
		t.Fatalf("expected nil error (log failure non-fatal), got: %v", err)
	}
	if len(result.PNGPreview) == 0 {
		t.Error("expected non-empty PNGPreview")
	}
	if result.Response.URL == "" {
		t.Error("expected non-empty URL")
	}
	if len(result.Hash8) != 8 {
		t.Errorf("Hash8 length = %d, want 8", len(result.Hash8))
	}
}
