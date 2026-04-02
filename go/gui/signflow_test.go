package gui

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
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

	result, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, logger)
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

	_, err := executeSignFlow(core.SignRequest{}, "", openAdapter, dummyReadPin, nil)
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

	_, err := executeSignFlow(core.SignRequest{}, "", openAdapter, dummyReadPin, logger)
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

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, logger)
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

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, logger)
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

	_, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, logger)
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
	_, err := executeSignFlow(req, "", openAdapter, dummyReadPin, logger)
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
	result, err := executeSignFlow(req, logPath, openAdapter, dummyReadPin, logger)
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
