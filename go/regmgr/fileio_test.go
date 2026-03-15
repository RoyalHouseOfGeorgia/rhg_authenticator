package regmgr

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

func validRegistryJSON() []byte {
	return []byte(`{
		"keys": [{
			"authority": "Test Authority",
			"from": "2025-01-01",
			"to": null,
			"algorithm": "Ed25519",
			"public_key": "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
			"note": "Test key"
		}]
	}`)
}

func validRegistry() core.Registry {
	return core.Registry{
		Keys: []core.KeyEntry{{
			Authority: "Test Authority",
			From:      "2025-01-01",
			To:        nil,
			Algorithm: "Ed25519",
			PublicKey:  "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
			Note:      "Test key",
		}},
	}
}

// --- FetchRegistry tests ---

func TestFetchRegistry_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	reg, err := FetchRegistry(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
	if reg.Keys[0].Authority != "Test Authority" {
		t.Errorf("authority = %q, want %q", reg.Keys[0].Authority, "Test Authority")
	}
}

func TestFetchRegistry_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %v, want containing %q", err, "HTTP 404")
	}
}

func TestFetchRegistry_HTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %v, want containing %q", err, "HTTP 500")
	}
}

func TestFetchRegistry_MissingContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Type header set explicitly.
		// Go's default is text/plain for small bodies.
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusOK)
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for missing Content-Type")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error = %v, want containing %q", err, "Content-Type")
	}
}

func TestFetchRegistry_WrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for wrong Content-Type")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error = %v, want containing %q", err, "Content-Type")
	}
}

func TestFetchRegistry_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- ReadRegistry tests ---

func TestReadRegistry_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(path, validRegistryJSON(), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	reg, err := ReadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
	if reg.Keys[0].Authority != "Test Authority" {
		t.Errorf("authority = %q, want %q", reg.Keys[0].Authority, "Test Authority")
	}
}

func TestReadRegistry_MissingFile(t *testing.T) {
	_, err := ReadRegistry("/nonexistent/path/registry.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading registry file") {
		t.Errorf("error = %v, want containing %q", err, "reading registry file")
	}
}

func TestReadRegistry_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	_, err := ReadRegistry(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- WriteRegistry tests ---

func TestWriteRegistry_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	reg := validRegistry()

	if err := WriteRegistry(path, reg); err != nil {
		t.Fatalf("WriteRegistry: %v", err)
	}

	got, err := ReadRegistry(path)
	if err != nil {
		t.Fatalf("ReadRegistry: %v", err)
	}

	if len(got.Keys) != len(reg.Keys) {
		t.Fatalf("key count = %d, want %d", len(got.Keys), len(reg.Keys))
	}
	if got.Keys[0].Authority != reg.Keys[0].Authority {
		t.Errorf("authority = %q, want %q", got.Keys[0].Authority, reg.Keys[0].Authority)
	}
	if got.Keys[0].PublicKey != reg.Keys[0].PublicKey {
		t.Errorf("public_key = %q, want %q", got.Keys[0].PublicKey, reg.Keys[0].PublicKey)
	}
}

func TestWriteRegistry_EmptyKeysRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	reg := core.Registry{Keys: []core.KeyEntry{}}

	err := WriteRegistry(path, reg)
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error = %v, want containing %q", err, "validation failed")
	}

	// File should not exist.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("file should not exist after validation failure")
	}
}

func TestWriteRegistry_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	reg := validRegistry()

	if err := WriteRegistry(path, reg); err != nil {
		t.Fatalf("WriteRegistry: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != fs.FileMode(0o600) {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestWriteRegistry_AtomicNoPartialWrite(t *testing.T) {
	// Write to a path inside a non-existent directory — rename will fail,
	// and the temp file should be cleaned up.
	dir := t.TempDir()
	badPath := filepath.Join(dir, "nonexistent-subdir", "registry.json")

	reg := validRegistry()
	err := WriteRegistry(badPath, reg)
	if err == nil {
		t.Fatal("expected error writing to non-existent directory")
	}

	// Verify no temp files were left behind in the parent dir.
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("reading dir: %v", readErr)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}
