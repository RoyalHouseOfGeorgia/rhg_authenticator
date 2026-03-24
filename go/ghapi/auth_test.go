// Tests in this file mutate package-level endpoint vars and MUST NOT use t.Parallel().
package ghapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sampleToken() Token {
	return Token{
		AccessToken: "gho_abc123",
		TokenType:   "bearer",
		Scope:       "repo,read:org",
		CreatedAt:   time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC),
	}
}

func mustMarshal(t *testing.T, tok Token) string {
	t.Helper()
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshaling token: %v", err)
	}
	return string(data)
}

// --- LoadToken tests ---

func TestLoadToken_NotExist(t *testing.T) {
	kr := NewFakeKeyring()
	dir := t.TempDir()

	_, err := LoadToken(kr, dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want wrapping os.ErrNotExist", err)
	}
}

func TestLoadToken_Valid(t *testing.T) {
	kr := NewFakeKeyring()
	tok := sampleToken()
	if err := kr.Set(serviceName, serviceKey, mustMarshal(t, tok)); err != nil {
		t.Fatalf("setting keyring: %v", err)
	}

	got, err := LoadToken(kr, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}
	if got.TokenType != tok.TokenType {
		t.Errorf("TokenType = %q, want %q", got.TokenType, tok.TokenType)
	}
	if got.Scope != tok.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, tok.Scope)
	}
	if !got.CreatedAt.Equal(tok.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, tok.CreatedAt)
	}
}

func TestLoadToken_Corrupt(t *testing.T) {
	kr := NewFakeKeyring()
	if err := kr.Set(serviceName, serviceKey, "not json!!!"); err != nil {
		t.Fatalf("setting keyring: %v", err)
	}

	_, err := LoadToken(kr, t.TempDir())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want wrapping os.ErrNotExist", err)
	}
}

func TestLoadToken_ZeroByte(t *testing.T) {
	kr := NewFakeKeyring()
	kr.SimulateError = ErrKeyNotFound
	dir := t.TempDir()

	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("writing zero-byte file: %v", err)
	}

	_, err := LoadToken(kr, dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want wrapping os.ErrNotExist", err)
	}

	// File should be deleted.
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("zero-byte file should have been deleted")
	}
}

func TestLoadToken_FallbackFile(t *testing.T) {
	kr := NewFakeKeyring()
	kr.SimulateError = ErrKeyNotFound
	dir := t.TempDir()
	tok := sampleToken()

	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte(mustMarshal(t, tok)), 0o600); err != nil {
		t.Fatalf("writing token file: %v", err)
	}

	got, err := LoadToken(kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}
}

func TestLoadToken_MissingCreatedAt(t *testing.T) {
	kr := NewFakeKeyring()
	// JSON without created_at — should unmarshal with zero time.
	raw := `{"access_token":"gho_old","token_type":"bearer","scope":"repo"}`
	if err := kr.Set(serviceName, serviceKey, raw); err != nil {
		t.Fatalf("setting keyring: %v", err)
	}

	got, err := LoadToken(kr, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != "gho_old" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "gho_old")
	}
	if !got.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want zero time", got.CreatedAt)
	}
}

func TestLoadToken_EmptyAccessToken(t *testing.T) {
	kr := NewFakeKeyring()
	// Token with empty AccessToken in keyring should be treated as missing.
	raw := `{"access_token":"","token_type":"bearer","scope":"repo"}`
	if err := kr.Set(serviceName, serviceKey, raw); err != nil {
		t.Fatalf("setting keyring: %v", err)
	}

	_, err := LoadToken(kr, t.TempDir())
	if err == nil {
		t.Fatal("expected error for empty AccessToken, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want wrapping os.ErrNotExist", err)
	}
}

func TestLoadToken_CorruptFile(t *testing.T) {
	kr := NewFakeKeyring()
	kr.SimulateError = ErrKeyNotFound
	dir := t.TempDir()

	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}

	_, err := LoadToken(kr, dir)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want wrapping os.ErrNotExist", err)
	}

	// Corrupt file should be deleted.
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("corrupt file should have been deleted")
	}
}

// --- SaveToken tests ---

func TestSaveToken_Keychain(t *testing.T) {
	kr := NewFakeKeyring()
	tok := sampleToken()

	if err := SaveToken(kr, t.TempDir(), tok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := kr.Get(serviceName, serviceKey)
	if err != nil {
		t.Fatalf("keyring Get failed: %v", err)
	}

	var got Token
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("unmarshaling stored token: %v", err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}
}

func TestSaveToken_FallbackFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission check not supported on Windows")
	}

	origGoos := goos
	goos = "linux"
	t.Cleanup(func() { goos = origGoos })

	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("keyring unavailable")
	dir := t.TempDir()
	tok := sampleToken()

	if err := SaveToken(kr, dir, tok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(dir, tokenFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != fs.FileMode(0o600) {
		t.Errorf("permissions = %o, want 0600", perm)
	}

	// Verify contents.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading token file: %v", err)
	}
	var got Token
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}

	// Verify no leftover .tmp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestSaveToken_MkdirAll(t *testing.T) {
	origGoos := goos
	goos = "linux"
	t.Cleanup(func() { goos = origGoos })

	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("keyring unavailable")
	dir := filepath.Join(t.TempDir(), "nested", "config")
	tok := sampleToken()

	if err := SaveToken(kr, dir, tok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	path := filepath.Join(dir, tokenFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("token file not created: %v", err)
	}
}

func TestSaveToken_BothFail(t *testing.T) {
	origGoos := goos
	goos = "linux"
	t.Cleanup(func() { goos = origGoos })

	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("keyring unavailable")

	// Create a regular file where a directory is expected — MkdirAll fails on all OSes.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := SaveToken(kr, filepath.Join(blocker, "subdir"), tok())
	if err == nil {
		t.Fatal("expected error when both keyring and file write fail")
	}
}

func TestSaveToken_NonLinuxNoFallback(t *testing.T) {
	origGoos := goos
	goos = "darwin"
	t.Cleanup(func() { goos = origGoos })

	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("keyring unavailable")

	err := SaveToken(kr, t.TempDir(), sampleToken())
	if err == nil {
		t.Fatal("expected error on non-linux when keyring fails")
	}
	if !strings.Contains(err.Error(), "keychain") {
		t.Errorf("error = %v, want containing 'keychain'", err)
	}
}

// --- ClearToken tests ---

func TestClearToken(t *testing.T) {
	kr := NewFakeKeyring()
	tok := sampleToken()
	dir := t.TempDir()

	// Set up token in both locations.
	if err := kr.Set(serviceName, serviceKey, mustMarshal(t, tok)); err != nil {
		t.Fatalf("setting keyring: %v", err)
	}
	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte(mustMarshal(t, tok)), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if err := ClearToken(kr, dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Keyring should be empty.
	if _, err := kr.Get(serviceName, serviceKey); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("keyring Get after clear: err = %v, want ErrKeyNotFound", err)
	}
	// File should be gone.
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("file should not exist after clear")
	}
}

func TestClearToken_ClearsBoth(t *testing.T) {
	t.Run("only_keyring", func(t *testing.T) {
		kr := NewFakeKeyring()
		if err := kr.Set(serviceName, serviceKey, "data"); err != nil {
			t.Fatalf("setting keyring: %v", err)
		}
		if err := ClearToken(kr, t.TempDir()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := kr.Get(serviceName, serviceKey); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("keyring should be empty after clear")
		}
	})

	t.Run("only_file", func(t *testing.T) {
		kr := NewFakeKeyring()
		dir := t.TempDir()
		path := filepath.Join(dir, tokenFileName)
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatalf("writing file: %v", err)
		}
		if err := ClearToken(kr, dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Error("file should be removed")
		}
	})

	t.Run("neither_exists", func(t *testing.T) {
		kr := NewFakeKeyring()
		if err := ClearToken(kr, t.TempDir()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClearToken_KeyringError(t *testing.T) {
	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("dbus failure")

	err := ClearToken(kr, t.TempDir())
	if err == nil {
		t.Fatal("expected error from keyring failure")
	}
	if !strings.Contains(err.Error(), "dbus failure") {
		t.Errorf("error = %v, want containing 'dbus failure'", err)
	}
}

func TestLoadToken_FileReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission tests not reliable on Windows")
	}
	kr := NewFakeKeyring()
	kr.SimulateError = ErrKeyNotFound
	dir := t.TempDir()

	// Create token file inside a directory with no read permission.
	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte(`{"access_token":"x"}`), 0o000); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	// Remove read permission from directory so ReadFile fails with permission error.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := LoadToken(kr, dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Error("error should NOT wrap os.ErrNotExist for permission failures")
	}
}

func TestClearToken_FileRemoveError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission tests not reliable on Windows")
	}
	kr := NewFakeKeyring()
	dir := t.TempDir()

	// Create file, then make dir unwritable so Remove fails with permission denied.
	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	err := ClearToken(kr, dir)
	if err == nil {
		t.Fatal("expected error from file removal")
	}
}

// --- FakeKeyring tests ---

func TestFakeKeyring_Basic(t *testing.T) {
	kr := NewFakeKeyring()

	// Get from empty keyring.
	_, err := kr.Get("svc", "key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get empty: err = %v, want ErrKeyNotFound", err)
	}

	// Set and Get.
	if err := kr.Set("svc", "key", "val"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := kr.Get("svc", "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "val" {
		t.Errorf("Get = %q, want %q", got, "val")
	}

	// Delete.
	if err := kr.Delete("svc", "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = kr.Get("svc", "key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrKeyNotFound", err)
	}

	// Delete non-existent.
	err = kr.Delete("svc", "key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Delete missing: err = %v, want ErrKeyNotFound", err)
	}
}

func TestFakeKeyring_SimulateError(t *testing.T) {
	kr := NewFakeKeyring()
	simErr := errors.New("simulated")
	kr.SimulateError = simErr

	if _, err := kr.Get("s", "k"); !errors.Is(err, simErr) {
		t.Errorf("Get: err = %v, want simulated", err)
	}
	if err := kr.Set("s", "k", "v"); !errors.Is(err, simErr) {
		t.Errorf("Set: err = %v, want simulated", err)
	}
	if err := kr.Delete("s", "k"); !errors.Is(err, simErr) {
		t.Errorf("Delete: err = %v, want simulated", err)
	}
}

// tok returns a minimal token for tests that don't care about specific values.
func tok() Token {
	return Token{AccessToken: "gho_test", TokenType: "bearer"}
}

// --- helpers for endpoint override ---

func overrideDeviceCodeEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := deviceCodeEndpoint
	deviceCodeEndpoint = url
	t.Cleanup(func() { deviceCodeEndpoint = orig })
}

func overrideAccessTokenEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := accessTokenEndpoint
	accessTokenEndpoint = url
	t.Cleanup(func() { accessTokenEndpoint = orig })
}

func overrideUserAPIEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := userAPIEndpoint
	userAPIEndpoint = url
	t.Cleanup(func() { userAPIEndpoint = orig })
}

func overrideTimeNow(t *testing.T, now time.Time) {
	t.Helper()
	orig := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = orig })
}

// --- RequestDeviceCode tests ---

func overrideClientID(t *testing.T, id string) {
	t.Helper()
	orig := ClientID
	ClientID = id
	t.Cleanup(func() { ClientID = orig })
}

func TestRequestDeviceCode_Success(t *testing.T) {
	overrideClientID(t, "test-client-id")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
		}
		if acc := r.Header.Get("Accept"); acc != "application/json" {
			t.Errorf("Accept = %q, want application/json", acc)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceCodeResponse{
			DeviceCode:      "dc_123",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://github.com/login/device",
			ExpiresIn:       900,
			Interval:        5,
		})
	}))
	defer srv.Close()
	overrideDeviceCodeEndpoint(t, srv.URL)

	dcr, err := RequestDeviceCode(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dcr.DeviceCode != "dc_123" {
		t.Errorf("DeviceCode = %q, want %q", dcr.DeviceCode, "dc_123")
	}
	if dcr.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want %q", dcr.UserCode, "ABCD-1234")
	}
	if dcr.VerificationURI != "https://github.com/login/device" {
		t.Errorf("VerificationURI = %q", dcr.VerificationURI)
	}
	if dcr.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d, want 900", dcr.ExpiresIn)
	}
	if dcr.Interval != 5 {
		t.Errorf("Interval = %d, want 5", dcr.Interval)
	}
}

func TestRequestDeviceCode_Error(t *testing.T) {
	overrideClientID(t, "test-client-id")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client_id"}`))
	}))
	defer srv.Close()
	overrideDeviceCodeEndpoint(t, srv.URL)

	_, err := RequestDeviceCode(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %v, want containing '400'", err)
	}
}

func TestRequestDeviceCode_Placeholder(t *testing.T) {
	origClientID := ClientID
	ClientID = "PLACEHOLDER"
	t.Cleanup(func() { ClientID = origClientID })

	_, err := RequestDeviceCode(context.Background())
	if err == nil {
		t.Fatal("expected error for PLACEHOLDER ClientID, got nil")
	}
	if !strings.Contains(err.Error(), "ClientID not configured") {
		t.Errorf("error = %v, want containing 'ClientID not configured'", err)
	}
}

func TestRequestDeviceCode_InvalidUserCode(t *testing.T) {
	overrideClientID(t, "test-client-id")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DeviceCodeResponse{
			DeviceCode:      "dc_123",
			UserCode:        "evil\ncode",
			VerificationURI: "https://github.com/login/device",
			ExpiresIn:       900,
			Interval:        5,
		})
	}))
	defer srv.Close()
	overrideDeviceCodeEndpoint(t, srv.URL)

	_, err := RequestDeviceCode(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid user code")
	}
	if !strings.Contains(err.Error(), "invalid user code format") {
		t.Errorf("error = %v, want containing 'invalid user code format'", err)
	}
}

// instantSleep returns immediately unless the context is cancelled.
func instantSleep(ctx context.Context, _ time.Duration) error {
	return ctx.Err()
}

// --- PollForToken tests ---

func TestPollForToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_new","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_new" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_new")
	}
	if tok.TokenType != "bearer" {
		t.Errorf("TokenType = %q, want %q", tok.TokenType, "bearer")
	}
	if tok.Scope != "public_repo" {
		t.Errorf("Scope = %q, want %q", tok.Scope, "public_repo")
	}
	if tok.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestPollForToken_Pending(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n <= 2 {
			fmt.Fprintf(w, `{"error":"authorization_pending"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"gho_ok","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 30, instantSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_ok" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_ok")
	}
	if got := count.Load(); got != 3 {
		t.Errorf("poll count = %d, want 3", got)
	}
}

func TestPollForToken_SlowDown(t *testing.T) {
	var pollCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pollCount++
		w.Header().Set("Content-Type", "application/json")
		if pollCount == 1 {
			fmt.Fprintf(w, `{"error":"slow_down"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"gho_sd","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	// Recording sleep that captures requested durations.
	var sleepDurations []time.Duration
	recordingSleep := func(ctx context.Context, d time.Duration) error {
		sleepDurations = append(sleepDurations, d)
		return ctx.Err()
	}

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 30, recordingSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_sd" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_sd")
	}
	if pollCount != 2 {
		t.Fatalf("poll count = %d, want 2", pollCount)
	}
	// First sleep: 1s (initial interval). After slow_down, second sleep: 6s (1+5).
	if len(sleepDurations) != 2 {
		t.Fatalf("sleep count = %d, want 2", len(sleepDurations))
	}
	if sleepDurations[0] != 1*time.Second {
		t.Errorf("first sleep = %v, want 1s", sleepDurations[0])
	}
	if sleepDurations[1] != 6*time.Second {
		t.Errorf("second sleep = %v, want 6s (1+5 from slow_down)", sleepDurations[1])
	}
}

func TestPollForToken_SlowDownCapped(t *testing.T) {
	// Start with interval=58. After slow_down (+5 = 63), should be capped at 60.
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Content-Type", "application/json")
		if count == 1 {
			fmt.Fprintf(w, `{"error":"slow_down"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"gho_cap","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	var sleepDurations []time.Duration
	recordingSleep := func(ctx context.Context, d time.Duration) error {
		sleepDurations = append(sleepDurations, d)
		return ctx.Err()
	}

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 58, 120, recordingSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_cap" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_cap")
	}
	// First sleep: 58s. After slow_down, 58+5=63 → capped to 60.
	if len(sleepDurations) != 2 {
		t.Fatalf("sleep count = %d, want 2", len(sleepDurations))
	}
	if sleepDurations[1] != 60*time.Second {
		t.Errorf("second sleep = %v, want 60s (capped from 63)", sleepDurations[1])
	}
}

func TestPollForToken_MultipleSlowDown(t *testing.T) {
	var pollCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pollCount++
		w.Header().Set("Content-Type", "application/json")
		if pollCount <= 2 {
			fmt.Fprintf(w, `{"error":"slow_down"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"gho_ms","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	var sleepDurations []time.Duration
	recordingSleep := func(ctx context.Context, d time.Duration) error {
		sleepDurations = append(sleepDurations, d)
		return ctx.Err()
	}

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 60, recordingSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_ms" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_ms")
	}
	if pollCount != 3 {
		t.Errorf("poll count = %d, want 3", pollCount)
	}
	// interval: 1 → 6 (after 1st slow_down) → 11 (after 2nd slow_down)
	if len(sleepDurations) != 3 {
		t.Fatalf("sleep count = %d, want 3", len(sleepDurations))
	}
	if sleepDurations[0] != 1*time.Second {
		t.Errorf("sleep[0] = %v, want 1s", sleepDurations[0])
	}
	if sleepDurations[1] != 6*time.Second {
		t.Errorf("sleep[1] = %v, want 6s", sleepDurations[1])
	}
	if sleepDurations[2] != 11*time.Second {
		t.Errorf("sleep[2] = %v, want 11s", sleepDurations[2])
	}
}

func TestPollForToken_Expired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"expired_token"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %v, want containing 'expired'", err)
	}
}

func TestPollForToken_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"access_denied"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("error = %v, want containing 'denied'", err)
	}
}

func TestPollForToken_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"authorization_pending"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay.
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	_, err := pollForTokenInternal(ctx, "dc_123", 1, 60, instantSleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestPollForToken_UnknownError(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"something_unexpected"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "something_unexpected") {
		t.Errorf("error = %v, want containing 'something_unexpected'", err)
	}
	// Should stop after first unknown error, not keep polling.
	if got := count.Load(); got != 1 {
		t.Errorf("poll count = %d, want 1 (should stop on unknown error)", got)
	}
}

func TestPollForToken_ExpiresInDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"authorization_pending"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	start := time.Now()
	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 1, instantSleep)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
	// Should time out within ~2 seconds (1s expiresIn + slack).
	if elapsed > 5*time.Second {
		t.Errorf("elapsed = %v, should have timed out quickly", elapsed)
	}
}

func TestPollForToken_ExpiresInNonPositive(t *testing.T) {
	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 0, instantSleep)
	if err == nil {
		t.Fatal("expected error for expiresIn=0, got nil")
	}
	if !strings.Contains(err.Error(), "positive") {
		t.Errorf("error = %v, want containing 'positive'", err)
	}
}

func TestPollForToken_IntervalNonPositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_def","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	// Verify that interval=0 defaults to 5 seconds via recording sleep.
	var sleepDurations []time.Duration
	recordingSleep := func(ctx context.Context, d time.Duration) error {
		sleepDurations = append(sleepDurations, d)
		return ctx.Err()
	}

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 0, 30, recordingSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_def" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_def")
	}
	if len(sleepDurations) != 1 {
		t.Fatalf("sleep count = %d, want 1", len(sleepDurations))
	}
	if sleepDurations[0] != 5*time.Second {
		t.Errorf("sleep duration = %v, want 5s (default interval)", sleepDurations[0])
	}
}

// --- ValidateToken tests ---

func TestValidateToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer gho_valid" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer gho_valid")
		}
		if acc := r.Header.Get("Accept"); acc != "application/vnd.github+json" {
			t.Errorf("Accept = %q, want application/vnd.github+json", acc)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"testuser","id":12345}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	login, err := ValidateToken(context.Background(), Token{AccessToken: "gho_valid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if login != "testuser" {
		t.Errorf("login = %q, want %q", login, "testuser")
	}
}

func TestValidateToken_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	_, err := ValidateToken(context.Background(), Token{AccessToken: "gho_bad"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized = false, want true; error = %v", err)
	}
}

func TestValidateToken_NetworkError(t *testing.T) {
	// Use an unreachable address.
	overrideUserAPIEndpoint(t, "http://127.0.0.1:1")

	_, err := ValidateToken(context.Background(), Token{AccessToken: "gho_net"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should NOT be an APIError (it's a network error).
	if IsUnauthorized(err) {
		t.Error("network error should not be treated as unauthorized")
	}
	var ae *APIError
	if errors.As(err, &ae) {
		t.Error("network error should not be an APIError")
	}
}

func TestValidateToken_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled.

	overrideUserAPIEndpoint(t, "http://127.0.0.1:1")

	_, err := ValidateToken(ctx, Token{AccessToken: "gho_timeout"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestValidateToken_EmptyLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"","id":0}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	_, err := ValidateToken(context.Background(), Token{AccessToken: "gho_empty"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing login") {
		t.Errorf("error = %v, want containing 'missing login'", err)
	}
}

func TestValidateToken_InvalidLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"evil\nuser","id":1}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	_, err := ValidateToken(context.Background(), Token{AccessToken: "gho_bad"})
	if err == nil {
		t.Fatal("expected error for invalid login format")
	}
	if !strings.Contains(err.Error(), "invalid GitHub login format") {
		t.Errorf("error = %v, want containing 'invalid GitHub login format'", err)
	}
}

// --- RestoreSession tests ---

func TestRestoreSession_ValidReachable(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"login":"ghuser"}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	kr := NewFakeKeyring()
	dir := t.TempDir()
	tkn := sampleToken()
	if err := SaveToken(kr, dir, tkn); err != nil {
		t.Fatalf("saving token: %v", err)
	}

	gotTok, username, loggedIn, offline, err := RestoreSession(context.Background(), kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if username != "ghuser" {
		t.Errorf("username = %q, want %q", username, "ghuser")
	}
	if gotTok.AccessToken != tkn.AccessToken {
		t.Errorf("AccessToken = %q, want %q", gotTok.AccessToken, tkn.AccessToken)
	}
}

func TestRestoreSession_ValidUnreachable(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC))
	overrideUserAPIEndpoint(t, "http://127.0.0.1:1")

	kr := NewFakeKeyring()
	dir := t.TempDir()
	tkn := sampleToken()
	if err := SaveToken(kr, dir, tkn); err != nil {
		t.Fatalf("saving token: %v", err)
	}

	gotTok, username, loggedIn, offline, err := RestoreSession(context.Background(), kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if !offline {
		t.Error("offline = false, want true")
	}
	if username != "" {
		t.Errorf("username = %q, want empty", username)
	}
	if gotTok.AccessToken != tkn.AccessToken {
		t.Errorf("AccessToken = %q, want %q", gotTok.AccessToken, tkn.AccessToken)
	}
}

func TestRestoreSession_Expired401(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"message":"Bad credentials"}`)
	}))
	defer srv.Close()
	overrideUserAPIEndpoint(t, srv.URL)

	kr := NewFakeKeyring()
	dir := t.TempDir()
	tkn := sampleToken()
	if err := SaveToken(kr, dir, tkn); err != nil {
		t.Fatalf("saving token: %v", err)
	}

	_, username, loggedIn, offline, err := RestoreSession(context.Background(), kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loggedIn {
		t.Error("loggedIn = true, want false")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if username != "" {
		t.Errorf("username = %q, want empty", username)
	}

	// Token should be cleared.
	_, loadErr := LoadToken(kr, dir)
	if !errors.Is(loadErr, os.ErrNotExist) {
		t.Errorf("token should be cleared after 401, LoadToken err = %v", loadErr)
	}
}

func TestRestoreSession_MissingFile(t *testing.T) {
	kr := NewFakeKeyring()
	dir := t.TempDir()

	_, username, loggedIn, offline, err := RestoreSession(context.Background(), kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loggedIn {
		t.Error("loggedIn = true, want false")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if username != "" {
		t.Errorf("username = %q, want empty", username)
	}
}

func TestRestoreSession_ContextTimeout(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC))
	// Use an already-cancelled context so ValidateToken fails immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// We still need a valid userAPIEndpoint even though it won't be reached.
	overrideUserAPIEndpoint(t, "http://127.0.0.1:1")

	kr := NewFakeKeyring()
	dir := t.TempDir()
	tkn := sampleToken()
	if err := SaveToken(kr, dir, tkn); err != nil {
		t.Fatalf("saving token: %v", err)
	}

	gotTok, username, loggedIn, offline, err := RestoreSession(ctx, kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if !offline {
		t.Error("offline = false, want true")
	}
	if username != "" {
		t.Errorf("username = %q, want empty", username)
	}
	if gotTok.AccessToken != tkn.AccessToken {
		t.Errorf("token should be preserved when offline")
	}
}

// --- M1: hasRequiredScope tests ---

func TestHasRequiredScope(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  bool
	}{
		{"empty scope", "", true},
		{"public_repo", "public_repo", true},
		{"repo", "repo", true},
		{"multi with public_repo", "read:org, public_repo", true},
		{"multi with repo", "read:org,repo", true},
		{"read:org only", "read:org", false},
		{"public_repo_admin not a match", "public_repo_admin", false},
		{"repo_deployment not a match", "repo_deployment", false},
		{"trailing spaces", "  public_repo  ", true},
		{"space-delimited", "read:org public_repo", true},
		{"space-delimited repo", "read:org repo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRequiredScope(tt.scope)
			if got != tt.want {
				t.Errorf("hasRequiredScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestPollForToken_WrongScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_bad","token_type":"bearer","scope":"read:org"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	_, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err == nil {
		t.Fatal("expected error for wrong scope")
	}
	if !strings.Contains(err.Error(), "missing required scope") {
		t.Errorf("error = %v, want containing 'missing required scope'", err)
	}
}

func TestPollForToken_MultiScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_multi","token_type":"bearer","scope":"read:org, public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_multi" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_multi")
	}
}

func TestPollForToken_RepoScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_repo","token_type":"bearer","scope":"repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 10, instantSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_repo" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_repo")
	}
}

// --- M6: Token redaction tests ---

func TestToken_StringRedaction(t *testing.T) {
	tok := Token{
		AccessToken: "gho_secret123",
		TokenType:   "bearer",
		Scope:       "public_repo",
	}
	s := fmt.Sprintf("%v", tok)
	if strings.Contains(s, "gho_secret123") {
		t.Errorf("String() exposes access token: %s", s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("String() missing [REDACTED]: %s", s)
	}
	if !strings.Contains(s, "bearer") {
		t.Errorf("String() missing TokenType: %s", s)
	}
	if !strings.Contains(s, "public_repo") {
		t.Errorf("String() missing Scope: %s", s)
	}
}

func TestToken_GoStringRedaction(t *testing.T) {
	tok := Token{
		AccessToken: "gho_secret123",
		TokenType:   "bearer",
		Scope:       "public_repo",
	}
	s := fmt.Sprintf("%#v", tok)
	if strings.Contains(s, "gho_secret123") {
		t.Errorf("GoString() exposes access token: %s", s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("GoString() missing [REDACTED]: %s", s)
	}
}

// --- M8: ExpiresIn cap test ---

func TestPollForToken_ExpiresInCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"gho_cap","token_type":"bearer","scope":"public_repo"}`)
	}))
	defer srv.Close()
	overrideAccessTokenEndpoint(t, srv.URL)

	// Recording sleep that captures the context deadline.
	var ctxDeadline time.Time
	recordingSleep := func(ctx context.Context, d time.Duration) error {
		if dl, ok := ctx.Deadline(); ok {
			ctxDeadline = dl
		}
		return ctx.Err()
	}

	start := time.Now()
	tok, err := pollForTokenInternal(context.Background(), "dc_123", 1, 9999, recordingSleep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "gho_cap" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "gho_cap")
	}

	// The context deadline should be at most 1800s from start.
	if ctxDeadline.IsZero() {
		t.Fatal("context deadline not captured")
	}
	maxDeadline := start.Add(1800*time.Second + 5*time.Second) // 5s slack
	if ctxDeadline.After(maxDeadline) {
		t.Errorf("context deadline %v is more than 1800s from start %v", ctxDeadline, start)
	}
}

// --- Finding #15: LoadToken keyring error handling ---

func TestLoadToken_KeyringError_NotSwallowed(t *testing.T) {
	kr := NewFakeKeyring()
	kr.SimulateError = errors.New("dbus connection refused")
	dir := t.TempDir()

	// Write a valid token file — if the keyring error were swallowed,
	// LoadToken would fall through and return this file token.
	tok := sampleToken()
	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte(mustMarshal(t, tok)), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := LoadToken(kr, dir)
	if err == nil {
		t.Fatal("expected error from keyring failure, got nil")
	}
	if !strings.Contains(err.Error(), "keyring access failed") {
		t.Errorf("error = %v, want containing 'keyring access failed'", err)
	}
	if !strings.Contains(err.Error(), "dbus connection refused") {
		t.Errorf("error = %v, want containing original error 'dbus connection refused'", err)
	}
}

func TestLoadToken_ErrKeyNotFound_FallsThrough(t *testing.T) {
	kr := NewFakeKeyring() // empty keyring returns ErrKeyNotFound
	dir := t.TempDir()

	tok := sampleToken()
	path := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(path, []byte(mustMarshal(t, tok)), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	got, err := LoadToken(kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != tok.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, tok.AccessToken)
	}
}

// --- Finding #8: Token expiry ---

func TestIsTokenExpired_Fresh(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC))
	tok := Token{
		AccessToken: "gho_fresh",
		CreatedAt:   time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
	}
	if isTokenExpired(tok) {
		t.Error("token created 1 day ago should not be expired")
	}
}

func TestIsTokenExpired_Old(t *testing.T) {
	overrideTimeNow(t, time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC))
	tok := Token{
		AccessToken: "gho_old",
		CreatedAt:   time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), // 102 days ago
	}
	if !isTokenExpired(tok) {
		t.Error("token created 102 days ago should be expired")
	}
}

func TestIsTokenExpired_ZeroCreatedAt(t *testing.T) {
	tok := Token{
		AccessToken: "gho_nots",
	}
	if !isTokenExpired(tok) {
		t.Error("token with zero CreatedAt should be expired")
	}
}

func TestIsTokenExpired_ExactBoundary(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	overrideTimeNow(t, created.Add(maxTokenAge))
	tok := Token{AccessToken: "gho_edge", CreatedAt: created}
	// Exactly at maxTokenAge — not expired (> not >=).
	if isTokenExpired(tok) {
		t.Error("token at exactly maxTokenAge boundary should not be expired")
	}

	overrideTimeNow(t, created.Add(maxTokenAge+time.Second))
	if !isTokenExpired(tok) {
		t.Error("token 1s past maxTokenAge should be expired")
	}
}

func TestRestoreSession_ExpiredToken(t *testing.T) {
	// Set time to 91 days after the sampleToken's CreatedAt.
	overrideTimeNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))

	kr := NewFakeKeyring()
	dir := t.TempDir()
	tkn := sampleToken() // CreatedAt: 2026-03-15
	if err := SaveToken(kr, dir, tkn); err != nil {
		t.Fatalf("saving token: %v", err)
	}

	_, username, loggedIn, offline, err := RestoreSession(context.Background(), kr, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loggedIn {
		t.Error("loggedIn = true, want false for expired token")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if username != "" {
		t.Errorf("username = %q, want empty", username)
	}

	// Token should be cleared.
	_, loadErr := LoadToken(kr, dir)
	if !errors.Is(loadErr, os.ErrNotExist) {
		t.Errorf("token should be cleared after expiry, LoadToken err = %v", loadErr)
	}
}
