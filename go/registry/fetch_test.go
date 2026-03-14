package registry

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// testPubKey is a 32-byte Ed25519 public key for testing.
var testPubKey = [32]byte{
	0xfc, 0xf8, 0xd3, 0xfa, 0x3d, 0xf8, 0xdb, 0x05,
	0x99, 0xca, 0x96, 0xf4, 0x9b, 0xfe, 0x0c, 0x48,
	0x1b, 0x05, 0x84, 0x7a, 0xeb, 0xab, 0x3a, 0x68,
	0x4d, 0xed, 0xab, 0x67, 0xd8, 0x5f, 0xd1, 0x75,
}

func testPubKeyB64() string {
	return base64.StdEncoding.EncodeToString(testPubKey[:])
}

func validRegistryJSON() []byte {
	return []byte(`{
		"keys": [{
			"authority": "Test Authority",
			"from": "2025-01-01",
			"to": null,
			"algorithm": "Ed25519",
			"public_key": "` + testPubKeyB64() + `",
			"note": "Test key"
		}]
	}`)
}

func validRegistryJSONWithDates(from, to string) []byte {
	toVal := "null"
	if to != "" {
		toVal = `"` + to + `"`
	}
	return []byte(`{
		"keys": [{
			"authority": "Test Authority",
			"from": "` + from + `",
			"to": ` + toVal + `,
			"algorithm": "Ed25519",
			"public_key": "` + testPubKeyB64() + `",
			"note": "Test key"
		}]
	}`)
}

func TestFetchRegistry_RemoteSuccess(t *testing.T) {
	body := validRegistryJSON()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	reg, source, err := FetchRegistry(srv.URL, cachePath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "remote" {
		t.Errorf("expected source 'remote', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
	if reg.Keys[0].Authority != "Test Authority" {
		t.Errorf("authority = %q", reg.Keys[0].Authority)
	}
}

func TestFetchRegistry_RemoteSuccess_CacheWritten(t *testing.T) {
	body := validRegistryJSON()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	_, _, err := FetchRegistry(srv.URL, cachePath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cache file was written.
	cached, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	// Verify cached content is valid registry JSON.
	var reg core.Registry
	if err := json.Unmarshal(cached, &reg); err != nil {
		t.Fatalf("cached file is not valid JSON: %v", err)
	}
	if len(reg.Keys) != 1 {
		t.Errorf("cached registry should have 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_RemoteFail_CacheHit(t *testing.T) {
	// No server running — remote will fail.
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	// Pre-populate cache.
	if err := os.WriteFile(cachePath, validRegistryJSON(), 0o600); err != nil {
		t.Fatalf("writing cache: %v", err)
	}

	reg, source, err := FetchRegistry("http://127.0.0.1:1/nonexistent", cachePath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "cache" {
		t.Errorf("expected source 'cache', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_RemoteFail_CacheMiss_Embedded(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")
	// No cache file, no server.

	reg, source, err := FetchRegistry("http://127.0.0.1:1/nonexistent", cachePath, validRegistryJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "embedded" {
		t.Errorf("expected source 'embedded', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_RemoteFail_CorruptedCache_Embedded(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	// Write corrupted cache.
	if err := os.WriteFile(cachePath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing cache: %v", err)
	}

	reg, source, err := FetchRegistry("http://127.0.0.1:1/nonexistent", cachePath, validRegistryJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "embedded" {
		t.Errorf("expected source 'embedded', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_AllFail(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	_, _, err := FetchRegistry("http://127.0.0.1:1/nonexistent", cachePath, []byte("bad"))
	if err == nil {
		t.Fatal("expected error when all sources fail")
	}
	if !strings.Contains(err.Error(), "all registry sources failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestFetchRegistry_RemoteInvalidJSON_FallsToCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	// Pre-populate cache.
	if err := os.WriteFile(cachePath, validRegistryJSON(), 0o600); err != nil {
		t.Fatalf("writing cache: %v", err)
	}

	reg, source, err := FetchRegistry(srv.URL, cachePath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "cache" {
		t.Errorf("expected source 'cache', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_RemoteHTTPError_FallsThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	reg, source, err := FetchRegistry(srv.URL, cachePath, validRegistryJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "embedded" {
		t.Errorf("expected source 'embedded', got %q", source)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_RemoteInvalidRegistry_NoCacheWritten(t *testing.T) {
	// Remote returns valid JSON but invalid registry (empty keys).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys": []}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	_, source, err := FetchRegistry(srv.URL, cachePath, validRegistryJSON())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != "embedded" {
		t.Errorf("expected source 'embedded', got %q", source)
	}

	// Cache should NOT have been written since remote was invalid.
	if _, err := os.Stat(cachePath); err == nil {
		t.Error("cache file should not exist for invalid remote registry")
	}
}

// --- FindMatchingAuthorityAt tests (deterministic date) ---

func TestFindMatchingAuthorityAt_Match(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	authority, err := FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authority != "Test Authority" {
		t.Errorf("expected 'Test Authority', got %q", authority)
	}
}

func TestFindMatchingAuthorityAt_NoMatch_WrongKey(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	wrongKey := [32]byte{0x01, 0x02, 0x03}
	_, err = FindMatchingAuthorityAt(reg, wrongKey, "2026-03-14")
	if err == nil {
		t.Fatal("expected error for non-matching key")
	}
	if !strings.Contains(err.Error(), "no active registry entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFindMatchingAuthorityAt_Expired(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSONWithDates("2025-01-01", "2025-12-31"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Date is after the "to" field.
	_, err = FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err == nil {
		t.Fatal("expected error for expired key")
	}
	if !strings.Contains(err.Error(), "no active registry entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFindMatchingAuthorityAt_NotYetValid(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSONWithDates("2027-01-01", ""))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err = FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err == nil {
		t.Fatal("expected error for not-yet-valid key")
	}
	if !strings.Contains(err.Error(), "no active registry entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFindMatchingAuthorityAt_SkipsDecodeError(t *testing.T) {
	// Registry with a bad public key entry followed by a good one.
	data := []byte(`{
		"keys": [
			{
				"authority": "Bad Entry",
				"from": "2025-01-01",
				"to": null,
				"algorithm": "Ed25519",
				"public_key": "not-valid-base64!!!",
				"note": "bad key"
			},
			{
				"authority": "Good Entry",
				"from": "2025-01-01",
				"to": null,
				"algorithm": "Ed25519",
				"public_key": "` + testPubKeyB64() + `",
				"note": "good key"
			}
		]
	}`)
	reg, err := core.ValidateRegistry(data)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	authority, err := FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authority != "Good Entry" {
		t.Errorf("expected 'Good Entry', got %q", authority)
	}
}

func TestFindMatchingAuthorityAt_MultipleKeys_FirstActiveMatch(t *testing.T) {
	data := []byte(`{
		"keys": [
			{
				"authority": "Expired Authority",
				"from": "2024-01-01",
				"to": "2024-12-31",
				"algorithm": "Ed25519",
				"public_key": "` + testPubKeyB64() + `",
				"note": "expired"
			},
			{
				"authority": "Active Authority",
				"from": "2025-01-01",
				"to": null,
				"algorithm": "Ed25519",
				"public_key": "` + testPubKeyB64() + `",
				"note": "active"
			}
		]
	}`)
	reg, err := core.ValidateRegistry(data)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	authority, err := FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authority != "Active Authority" {
		t.Errorf("expected 'Active Authority', got %q", authority)
	}
}

func TestFindMatchingAuthority_UsesToday(t *testing.T) {
	// This test just verifies FindMatchingAuthority doesn't panic and uses time.Now.
	// We use a key with from=2020-01-01 and to=null so it should always match.
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	authority, err := FindMatchingAuthority(reg, testPubKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authority != "Test Authority" {
		t.Errorf("expected 'Test Authority', got %q", authority)
	}
}

func TestFindMatchingAuthority_NoMatch(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	wrongKey := [32]byte{0xde, 0xad}
	_, err = FindMatchingAuthority(reg, wrongKey)
	if err == nil {
		t.Fatal("expected error for non-matching key")
	}
	if !strings.Contains(err.Error(), "no active registry entry") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFindMatchingAuthority_SkipsDecodeError(t *testing.T) {
	// Registry with only a bad public_key entry — should return error.
	data := []byte(`{
		"keys": [{
			"authority": "Bad",
			"from": "2025-01-01",
			"to": null,
			"algorithm": "Ed25519",
			"public_key": "not-valid-base64!!!",
			"note": ""
		}]
	}`)
	reg, err := core.ValidateRegistry(data)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err = FindMatchingAuthority(reg, testPubKey)
	if err == nil {
		t.Fatal("expected error when all entries have decode errors")
	}
}

func TestFetchRegistry_RemoteMalformedJSON_NoCacheWritten(t *testing.T) {
	// Remote returns malformed JSON (not valid JSON at all).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{this is not valid json"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	cachePath := filepath.Join(dir, "registry.cache.json")

	_, _, err := FetchRegistry(srv.URL, cachePath, validRegistryJSON())
	if err != nil {
		t.Fatalf("unexpected error (should fall back to embedded): %v", err)
	}

	// Cache file must NOT exist — malformed response should never be cached.
	if _, statErr := os.Stat(cachePath); statErr == nil {
		t.Error("cache file should not exist when remote returns malformed JSON")
	}
}

func TestFetchRegistry_DefaultRegistryURL(t *testing.T) {
	if DefaultRegistryURL != "https://verify.royalhouseofgeorgia.ge/keys/registry.json" {
		t.Errorf("unexpected default URL: %s", DefaultRegistryURL)
	}
}

func TestFetchRegistry_FetchTimeout(t *testing.T) {
	if FetchTimeout.Seconds() != 10 {
		t.Errorf("expected 10s timeout, got %v", FetchTimeout)
	}
}
