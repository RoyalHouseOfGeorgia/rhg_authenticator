package registry

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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

// --- FetchRegistry tests (remote only, no fallback) ---

func TestFetchRegistry_RemoteSuccess(t *testing.T) {
	body := validRegistryJSON()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
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
		t.Errorf("authority = %q", reg.Keys[0].Authority)
	}
}

func TestFetchRegistry_NetworkError(t *testing.T) {
	_, err := FetchRegistry("http://127.0.0.1:1/nonexistent")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestFetchRegistry_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should contain '404', got: %v", err)
	}
}

func TestFetchRegistry_HTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestFetchRegistry_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json {{"))
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
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
		t.Errorf("error should mention Content-Type, got: %v", err)
	}
}

func TestFetchRegistry_ContentTypeControlChars(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html\r\nInjected-Header: evil")
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for wrong Content-Type")
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "\r") || strings.Contains(errMsg, "\n") {
		t.Errorf("error message should not contain control characters, got: %q", errMsg)
	}
}

func TestFetchRegistry_ContentTypeWithCharset(t *testing.T) {
	body := validRegistryJSON()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(body)
	}))
	defer srv.Close()

	reg, err := FetchRegistry(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error for application/json with charset: %v", err)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
}

func TestFetchRegistry_ContentTypeVariant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json-patch+json")
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for application/json-patch+json")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error should mention Content-Type, got: %v", err)
	}
}

func TestFetchRegistry_MissingContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(validRegistryJSON())
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for missing Content-Type")
	}
}

func TestFetchRegistry_InvalidRegistrySchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys": []}`)) // empty keys — invalid
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid registry schema")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention validation, got: %v", err)
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

	_, err = FindMatchingAuthorityAt(reg, testPubKey, "2026-03-14")
	if err == nil {
		t.Fatal("expected error for expired key")
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
}

func TestFindMatchingAuthorityAt_SkipsDecodeError(t *testing.T) {
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
}

func TestFindMatchingAuthority_SkipsDecodeError(t *testing.T) {
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

// --- FindMatchingEntryAt tests ---

func TestFindMatchingEntryAt_Found(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	entry := FindMatchingEntryAt(reg, testPubKey, "2026-03-15")
	if entry == nil {
		t.Fatal("expected matching entry, got nil")
	}
	if entry.Authority != "Test Authority" {
		t.Errorf("authority = %q, want %q", entry.Authority, "Test Authority")
	}
}

func TestFindMatchingEntryAt_NotFound(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSON())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	wrongKey := [32]byte{0x01, 0x02, 0x03}
	entry := FindMatchingEntryAt(reg, wrongKey, "2026-03-15")
	if entry != nil {
		t.Errorf("expected nil for non-matching key, got: %+v", entry)
	}
}

func TestFindMatchingEntryAt_Expired(t *testing.T) {
	reg, err := core.ValidateRegistry(validRegistryJSONWithDates("2025-01-01", "2025-12-31"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	entry := FindMatchingEntryAt(reg, testPubKey, "2026-03-15")
	if entry != nil {
		t.Errorf("expected nil for expired entry, got: %+v", entry)
	}
}

// --- Size limit tests ---

func TestFetchRegistry_ExactlyMaxBytes(t *testing.T) {
	// Body at exactly maxRegistryBytes should pass the size check.
	// It won't be valid registry JSON, so we expect a validation error, not a size error.
	body := bytes.Repeat([]byte("x"), maxRegistryBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error (validation), got nil")
	}
	if strings.Contains(err.Error(), "exceeds") {
		t.Errorf("should not be a size error, got: %v", err)
	}
}

func TestFetchRegistry_OversizedResponse(t *testing.T) {
	// Body exceeding maxRegistryBytes by 1 must be rejected with a size error.
	body := bytes.Repeat([]byte("x"), maxRegistryBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchRegistry(srv.URL)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should contain 'exceeds', got: %v", err)
	}
}

// --- FetchRevocationList tests ---

func validRevocationJSON() []byte {
	return []byte(`{"revocations": [{"hash": "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc", "revoked_on": "2026-03-25"}]}`)
}

func TestFetchRevocationList_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(validRevocationJSON())
	}))
	defer srv.Close()

	list, err := FetchRevocationList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(list.Revocations))
	}
	if list.Revocations[0].Hash != "cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc" {
		t.Errorf("unexpected hash: %s", list.Revocations[0].Hash)
	}
	if list.Revocations[0].RevokedOn != "2026-03-25" {
		t.Errorf("unexpected revoked_on: %s", list.Revocations[0].RevokedOn)
	}
}

func TestFetchRevocationList_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	list, err := FetchRevocationList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error on 404: %v", err)
	}
	if list == nil {
		t.Fatal("expected non-nil list on 404")
	}
	if len(list.Revocations) != 0 {
		t.Errorf("expected empty revocations on 404, got %d", len(list.Revocations))
	}
}

func TestFetchRevocationList_500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain '500', got: %v", err)
	}
}

func TestFetchRevocationList_403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should contain '403', got: %v", err)
	}
}

func TestFetchRevocationList_NetworkError(t *testing.T) {
	_, err := FetchRevocationList("http://127.0.0.1:1/nonexistent")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestFetchRevocationList_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json {{"))
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention validation, got: %v", err)
	}
}

func TestFetchRevocationList_OversizedResponse(t *testing.T) {
	body := bytes.Repeat([]byte("x"), maxRegistryBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should contain 'exceeds', got: %v", err)
	}
}

func TestFetchRevocationList_InvalidSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revocations": [{"hash": "short", "revoked_on": "2026-03-25"}]}`))
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid schema")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention validation, got: %v", err)
	}
}

func TestFetchRevocationList_EmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revocations": []}`))
	}))
	defer srv.Close()

	list, err := FetchRevocationList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if list == nil {
		t.Fatal("expected non-nil list")
	}
	if len(list.Revocations) != 0 {
		t.Errorf("expected empty revocations, got %d", len(list.Revocations))
	}
}

func TestFetchRevocationList_ContentTypeGitHubRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.github.raw+json")
		w.Write(validRevocationJSON())
	}))
	defer srv.Close()

	list, err := FetchRevocationList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(list.Revocations))
	}
}

func TestFetchRevocationList_WrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(validRevocationJSON())
	}))
	defer srv.Close()

	_, err := FetchRevocationList(srv.URL)
	if err == nil {
		t.Fatal("expected error for wrong Content-Type")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error should mention Content-Type, got: %v", err)
	}
}

func TestDefaultRevocationURL(t *testing.T) {
	if DefaultRevocationURL != "https://verify.royalhouseofgeorgia.ge/keys/revocations.json" {
		t.Errorf("unexpected default revocation URL: %s", DefaultRevocationURL)
	}
}

// --- readLimitedBody tests ---

func TestReadLimitedBody_WithinLimit(t *testing.T) {
	body := strings.Repeat("x", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := readLimitedBody(resp, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != body {
		t.Errorf("body = %q, want %q", string(data), body)
	}
}

func TestReadLimitedBody_ExceedsLimit(t *testing.T) {
	body := strings.Repeat("x", 200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, err = readLimitedBody(resp, 100)
	if err == nil {
		t.Fatal("expected error for body exceeding limit")
	}
	if !strings.Contains(err.Error(), "100 byte limit") {
		t.Errorf("error = %q, want mention of byte limit", err.Error())
	}
}

func TestReadLimitedBody_ExactLimit(t *testing.T) {
	body := strings.Repeat("x", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := readLimitedBody(resp, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 100 {
		t.Errorf("body length = %d, want 100", len(data))
	}
}

func TestReadLimitedBody_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// empty response
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := readLimitedBody(resp, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("body length = %d, want 0", len(data))
	}
}

