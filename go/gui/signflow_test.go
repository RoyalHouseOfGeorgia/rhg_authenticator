package gui

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// mockSignAdapter implements core.SigningAdapter using an in-memory Ed25519 key.
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

// newTestKeyAndRegistry creates a matching Ed25519 key pair and a registry
// containing its public key with an open-ended validity period.
func newTestKeyAndRegistry() (ed25519.PrivateKey, core.Registry) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pubBytes := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	reg := core.Registry{
		Keys: []core.KeyEntry{{
			Authority: "Test Authority",
			From:      "2020-01-01",
			To:        nil,
			Algorithm: "Ed25519",
			PublicKey: pubB64,
			Note:      "test key",
		}},
	}
	return priv, reg
}

func dummyReadPin() (string, error) { return "123456", nil }

func TestExecuteSignFlow_HappyPath(t *testing.T) {
	priv, reg := newTestKeyAndRegistry()
	adapter := &mockSignAdapter{secretKey: priv}

	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	logPath := filepath.Join(tmpDir, "issuance.log")

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	result, err := executeSignFlow(req, reg, logPath, openAdapter, dummyReadPin, logger)
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

	_, err := executeSignFlow(core.SignRequest{}, core.Registry{}, "", openAdapter, dummyReadPin, nil)
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
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}

	_, err := executeSignFlow(core.SignRequest{}, core.Registry{}, "", openAdapter, dummyReadPin, logger)
	if err == nil {
		t.Fatal("expected error from ExportPublicKey")
	}
	if got := err.Error(); !strings.Contains(got,"export public key") {
		t.Errorf("error should contain 'export public key', got: %q", got)
	}
}

func TestExecuteSignFlow_KeyNotInRegistry(t *testing.T) {
	// Generate a key that is NOT in the registry.
	_, priv, _ := ed25519.GenerateKey(nil)
	adapter := &mockSignAdapter{secretKey: priv}
	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	emptyReg := core.Registry{Keys: []core.KeyEntry{}}

	_, err := executeSignFlow(core.SignRequest{}, emptyReg, "", openAdapter, dummyReadPin, nil)
	if err == nil {
		t.Fatal("expected error for key not in registry")
	}
	if got := err.Error(); !strings.Contains(got,"no active registry entry") {
		t.Errorf("error should contain 'no active registry entry', got: %q", got)
	}
}

func TestExecuteSignFlow_SignError(t *testing.T) {
	priv, reg := newTestKeyAndRegistry()
	adapter := &errorSignAdapter{secretKey: priv}
	openAdapter := func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
		return adapter, nopCloser{}, nil
	}

	tmpDir := t.TempDir()
	logger := &debugLogger{path: filepath.Join(tmpDir, "debug.log")}
	logPath := filepath.Join(tmpDir, "issuance.log")

	req := core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    "Distinguished service",
		Date:      "2026-03-14",
	}

	_, err := executeSignFlow(req, reg, logPath, openAdapter, dummyReadPin, logger)
	if err == nil {
		t.Fatal("expected error from SignBytes")
	}
	if got := err.Error(); !strings.Contains(got,"signing") {
		t.Errorf("error should relate to signing, got: %q", got)
	}
}

