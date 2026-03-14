package core

import (
	"encoding/base64"
	"strings"
	"testing"
)

// validRegistryJSON returns valid registry JSON for testing.
func validRegistryJSON() string {
	return `{
		"keys": [
			{
				"authority": "Test Authority",
				"from": "2025-01-01",
				"to": null,
				"algorithm": "Ed25519",
				"public_key": "/PjT+j342wWZypb0m/4MSBsFhHrrqzpoTe2rZ9hf0XU=",
				"note": "Test key"
			}
		]
	}`
}

func TestValidateRegistry_Valid(t *testing.T) {
	reg, err := ValidateRegistry([]byte(validRegistryJSON()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(reg.Keys))
	}
	k := reg.Keys[0]
	if k.Authority != "Test Authority" {
		t.Errorf("authority = %q", k.Authority)
	}
	if k.From != "2025-01-01" {
		t.Errorf("from = %q", k.From)
	}
	if k.To != nil {
		t.Errorf("to should be nil, got %v", *k.To)
	}
	if k.Algorithm != "Ed25519" {
		t.Errorf("algorithm = %q", k.Algorithm)
	}
	if k.Note != "Test key" {
		t.Errorf("note = %q", k.Note)
	}
}

func TestValidateRegistry_ValidWithTo(t *testing.T) {
	data := `{
		"keys": [{
			"authority": "Auth",
			"from": "2025-01-01",
			"to": "2025-12-31",
			"algorithm": "Ed25519",
			"public_key": "AAAA",
			"note": ""
		}]
	}`
	reg, err := ValidateRegistry([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Keys[0].To == nil || *reg.Keys[0].To != "2025-12-31" {
		t.Errorf("to should be 2025-12-31")
	}
}

func TestValidateRegistry_InvalidJSON(t *testing.T) {
	_, err := ValidateRegistry([]byte("not json"))
	if err == nil || err.Error() != "registry must be a plain object" {
		t.Fatalf("expected plain object error, got %v", err)
	}
}

func TestValidateRegistry_ArrayJSON(t *testing.T) {
	_, err := ValidateRegistry([]byte("[]"))
	if err == nil || err.Error() != "registry must be a plain object" {
		t.Fatalf("expected plain object error, got %v", err)
	}
}

func TestValidateRegistry_MissingKeys(t *testing.T) {
	_, err := ValidateRegistry([]byte(`{}`))
	if err == nil || err.Error() != "missing required field: keys" {
		t.Fatalf("expected missing keys error, got %v", err)
	}
}

func TestValidateRegistry_EmptyKeysArray(t *testing.T) {
	_, err := ValidateRegistry([]byte(`{"keys": []}`))
	if err == nil || err.Error() != "keys array must not be empty" {
		t.Fatalf("expected empty keys error, got %v", err)
	}
}

func TestValidateRegistry_KeysNotArray(t *testing.T) {
	_, err := ValidateRegistry([]byte(`{"keys": "not array"}`))
	if err == nil || err.Error() != "keys must be an array" {
		t.Fatalf("expected keys array error, got %v", err)
	}
}

func TestValidateRegistry_ExtraTopLevelField(t *testing.T) {
	_, err := ValidateRegistry([]byte(`{"keys": [], "extra": true}`))
	if err == nil || err.Error() != "unexpected field: extra" {
		t.Fatalf("expected unexpected field error, got %v", err)
	}
}

func TestValidateRegistry_EntryNotObject(t *testing.T) {
	_, err := ValidateRegistry([]byte(`{"keys": ["not an object"]}`))
	if err == nil || err.Error() != "keys[0] must be a plain object" {
		t.Fatalf("expected plain object error for entry, got %v", err)
	}
}

func TestValidateRegistry_EntryExtraField(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":"","extra":"x"}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "unexpected field: extra") {
		t.Fatalf("expected unexpected field error, got %v", err)
	}
}

func TestValidateRegistry_MissingAuthority(t *testing.T) {
	data := `{"keys": [{"from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: authority") {
		t.Fatalf("expected missing authority error, got %v", err)
	}
}

func TestValidateRegistry_EmptyAuthority(t *testing.T) {
	data := `{"keys": [{"authority":"","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "authority must not be empty") {
		t.Fatalf("expected empty authority error, got %v", err)
	}
}

func TestValidateRegistry_AuthorityNotString(t *testing.T) {
	data := `{"keys": [{"authority":123,"from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "authority must be a string") {
		t.Fatalf("expected string error, got %v", err)
	}
}

func TestValidateRegistry_MissingFrom(t *testing.T) {
	data := `{"keys": [{"authority":"A","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: from") {
		t.Fatalf("expected missing from error, got %v", err)
	}
}

func TestValidateRegistry_InvalidFromDate(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"not-a-date","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "invalid date for from") {
		t.Fatalf("expected invalid from date error, got %v", err)
	}
}

func TestValidateRegistry_FromNotString(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":123,"to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "from must be a string") {
		t.Fatalf("expected string error for from, got %v", err)
	}
}

func TestValidateRegistry_MissingTo(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: to") {
		t.Fatalf("expected missing to error, got %v", err)
	}
}

func TestValidateRegistry_ToNotStringOrNull(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":123,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "to must be a string or null") {
		t.Fatalf("expected string or null error for to, got %v", err)
	}
}

func TestValidateRegistry_InvalidToDate(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":"bad","algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "invalid date for to") {
		t.Fatalf("expected invalid to date error, got %v", err)
	}
}

func TestValidateRegistry_DateRangeInvalid(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-06-01","to":"2025-01-01","algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "invalid date range") {
		t.Fatalf("expected date range error, got %v", err)
	}
}

func TestValidateRegistry_MissingAlgorithm(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: algorithm") {
		t.Fatalf("expected missing algorithm error, got %v", err)
	}
}

func TestValidateRegistry_WrongAlgorithm(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"RSA","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "algorithm must be 'Ed25519'") {
		t.Fatalf("expected algorithm error, got %v", err)
	}
}

func TestValidateRegistry_MissingPublicKey(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: public_key") {
		t.Fatalf("expected missing public_key error, got %v", err)
	}
}

func TestValidateRegistry_EmptyPublicKey(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "public_key must not be empty") {
		t.Fatalf("expected empty public_key error, got %v", err)
	}
}

func TestValidateRegistry_PublicKeyNotString(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":123,"note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "public_key must be a string") {
		t.Fatalf("expected string error for public_key, got %v", err)
	}
}

func TestValidateRegistry_MissingNote(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA"}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: note") {
		t.Fatalf("expected missing note error, got %v", err)
	}
}

func TestValidateRegistry_NoteNotString(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":123}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "note must be a string") {
		t.Fatalf("expected string error for note, got %v", err)
	}
}

func TestValidateRegistry_EmptyNote(t *testing.T) {
	// Empty note is allowed.
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	reg, err := ValidateRegistry([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Keys[0].Note != "" {
		t.Errorf("note should be empty")
	}
}

// --- DecodePublicKey tests ---

func TestDecodePublicKey_Raw32Bytes(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	entry := KeyEntry{PublicKey: base64.StdEncoding.EncodeToString(raw)}
	result, err := DecodePublicKey(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 32; i++ {
		if result[i] != byte(i) {
			t.Fatalf("byte %d mismatch", i)
		}
	}
}

func TestDecodePublicKey_SPKI44Bytes(t *testing.T) {
	keyData := make([]byte, 32)
	for i := range keyData {
		keyData[i] = byte(i + 100)
	}
	spki := append([]byte(nil), ED25519SpkiPrefix...)
	spki = append(spki, keyData...)

	entry := KeyEntry{PublicKey: base64.StdEncoding.EncodeToString(spki)}
	result, err := DecodePublicKey(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 32; i++ {
		if result[i] != byte(i+100) {
			t.Fatalf("byte %d mismatch: got %d, want %d", i, result[i], i+100)
		}
	}
}

func TestDecodePublicKey_WrongSPKIPrefix(t *testing.T) {
	wrongPrefix := make([]byte, 44)
	wrongPrefix[0] = 0xFF // Wrong prefix
	entry := KeyEntry{PublicKey: base64.StdEncoding.EncodeToString(wrongPrefix)}
	_, err := DecodePublicKey(entry)
	if err == nil || !strings.Contains(err.Error(), "does not have expected Ed25519 SPKI prefix") {
		t.Fatalf("expected SPKI prefix error, got %v", err)
	}
}

func TestDecodePublicKey_WrongLength(t *testing.T) {
	data := make([]byte, 16) // Neither 32 nor 44
	entry := KeyEntry{PublicKey: base64.StdEncoding.EncodeToString(data)}
	_, err := DecodePublicKey(entry)
	if err == nil || !strings.Contains(err.Error(), "unexpected key length 16 bytes") {
		t.Fatalf("expected wrong length error, got %v", err)
	}
}

func TestDecodePublicKey_InvalidBase64(t *testing.T) {
	entry := KeyEntry{PublicKey: "not valid base64!!!"}
	_, err := DecodePublicKey(entry)
	if err == nil || !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("expected base64 error, got %v", err)
	}
}

func TestDecodePublicKey_TooLongInput(t *testing.T) {
	entry := KeyEntry{PublicKey: strings.Repeat("A", 257)}
	_, err := DecodePublicKey(entry)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("expected max length error, got %v", err)
	}
}

// --- FindKeysByAuthority tests ---

func TestFindKeysByAuthority_Match(t *testing.T) {
	reg := Registry{
		Keys: []KeyEntry{
			{Authority: "Alpha"},
			{Authority: "Beta"},
			{Authority: "Alpha"},
		},
	}
	results := FindKeysByAuthority(reg, "Alpha")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestFindKeysByAuthority_NoMatch(t *testing.T) {
	reg := Registry{
		Keys: []KeyEntry{
			{Authority: "Alpha"},
		},
	}
	results := FindKeysByAuthority(reg, "Gamma")
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestFindKeysByAuthority_CaseSensitive(t *testing.T) {
	reg := Registry{
		Keys: []KeyEntry{
			{Authority: "Alpha"},
		},
	}
	results := FindKeysByAuthority(reg, "alpha")
	if len(results) != 0 {
		t.Fatalf("expected 0 results (case sensitive), got %d", len(results))
	}
}

func TestFindKeysByAuthority_NFCNormalization(t *testing.T) {
	// NFD: e + combining accent (U+0065 U+0301) vs NFC: é (U+00E9)
	reg := Registry{
		Keys: []KeyEntry{
			{Authority: "caf\u00e9"}, // NFC form
		},
	}
	results := FindKeysByAuthority(reg, "cafe\u0301") // NFD form
	if len(results) != 1 {
		t.Fatalf("expected 1 result with NFC normalization, got %d", len(results))
	}
}

// --- IsDateInRange tests ---

func TestIsDateInRange_InRange(t *testing.T) {
	key := KeyEntry{From: "2025-01-01"}
	key.To = strPtr("2025-12-31")
	if !IsDateInRange("2025-06-15", key) {
		t.Error("expected true for date in range")
	}
}

func TestIsDateInRange_AtFromBoundary(t *testing.T) {
	key := KeyEntry{From: "2025-01-01"}
	key.To = strPtr("2025-12-31")
	if !IsDateInRange("2025-01-01", key) {
		t.Error("expected true for date at from boundary (inclusive)")
	}
}

func TestIsDateInRange_AtToBoundary(t *testing.T) {
	key := KeyEntry{From: "2025-01-01"}
	key.To = strPtr("2025-12-31")
	if !IsDateInRange("2025-12-31", key) {
		t.Error("expected true for date at to boundary (inclusive)")
	}
}

func TestIsDateInRange_BeforeFrom(t *testing.T) {
	key := KeyEntry{From: "2025-01-01"}
	key.To = strPtr("2025-12-31")
	if IsDateInRange("2024-12-31", key) {
		t.Error("expected false for date before from")
	}
}

func TestIsDateInRange_AfterTo(t *testing.T) {
	key := KeyEntry{From: "2025-01-01"}
	key.To = strPtr("2025-12-31")
	if IsDateInRange("2026-01-01", key) {
		t.Error("expected false for date after to")
	}
}

func TestIsDateInRange_NilTo(t *testing.T) {
	key := KeyEntry{From: "2025-01-01", To: nil}
	if !IsDateInRange("2099-12-31", key) {
		t.Error("expected true for nil to (no upper bound)")
	}
}

func TestIsDateInRange_InvalidDateFormat(t *testing.T) {
	key := KeyEntry{From: "2025-01-01", To: nil}
	if IsDateInRange("not-a-date", key) {
		t.Error("expected false for invalid date format")
	}
}

func TestIsDateInRange_ShortDate(t *testing.T) {
	key := KeyEntry{From: "2025-01-01", To: nil}
	if IsDateInRange("25-01-01", key) {
		t.Error("expected false for short date format")
	}
}

func strPtr(s string) *string {
	return &s
}

// --- ED25519SpkiPrefix tests ---

func TestED25519SpkiPrefix_Length(t *testing.T) {
	if len(ED25519SpkiPrefix) != 12 {
		t.Errorf("expected 12 bytes, got %d", len(ED25519SpkiPrefix))
	}
}

func TestValidateRegistry_MultipleEntries(t *testing.T) {
	data := `{"keys": [
		{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":"first"},
		{"authority":"B","from":"2025-06-01","to":"2025-12-31","algorithm":"Ed25519","public_key":"BBBB","note":"second"}
	]}`
	reg, err := ValidateRegistry([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reg.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(reg.Keys))
	}
}

func TestValidateRegistry_DateRangeEqual(t *testing.T) {
	// from == to should be valid (single-day validity).
	data := `{"keys": [{"authority":"A","from":"2025-06-01","to":"2025-06-01","algorithm":"Ed25519","public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err != nil {
		t.Fatalf("expected no error for from == to, got %v", err)
	}
}

func TestValidateRegistry_MaxKeysExactlyAtLimit(t *testing.T) {
	// Registry with exactly MaxRegistryKeys (1000) entries should pass.
	entries := make([]string, MaxRegistryKeys)
	for i := range entries {
		entries[i] = `{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}`
	}
	data := `{"keys": [` + strings.Join(entries, ",") + `]}`
	reg, err := ValidateRegistry([]byte(data))
	if err != nil {
		t.Fatalf("expected no error for %d keys, got %v", MaxRegistryKeys, err)
	}
	if len(reg.Keys) != MaxRegistryKeys {
		t.Errorf("expected %d keys, got %d", MaxRegistryKeys, len(reg.Keys))
	}
}

func TestValidateRegistry_MaxKeysExceedsLimit(t *testing.T) {
	// Registry with MaxRegistryKeys+1 (1001) entries should be rejected.
	count := MaxRegistryKeys + 1
	entries := make([]string, count)
	for i := range entries {
		entries[i] = `{"authority":"A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"AAAA","note":""}`
	}
	data := `{"keys": [` + strings.Join(entries, ",") + `]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil {
		t.Fatalf("expected error for %d keys exceeding maximum", count)
	}
	if !strings.Contains(err.Error(), "exceeding maximum") {
		t.Errorf("unexpected error message: %v", err)
	}
	if !strings.Contains(err.Error(), "1001") {
		t.Errorf("error should mention the actual count 1001: %v", err)
	}
}

func TestValidateRegistry_AlgorithmNotString(t *testing.T) {
	data := `{"keys": [{"authority":"A","from":"2025-01-01","to":null,"algorithm":123,"public_key":"AAAA","note":""}]}`
	_, err := ValidateRegistry([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "algorithm must be 'Ed25519'") {
		t.Fatalf("expected algorithm error, got %v", err)
	}
}
