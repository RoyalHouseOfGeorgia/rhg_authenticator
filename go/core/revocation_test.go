package core

import (
	"fmt"
	"strings"
	"testing"
)

// validRevocationJSON returns valid revocation list JSON for testing.
func validRevocationJSON() string {
	return `{
		"revocations": [
			{
				"hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"revoked_on": "2025-03-15"
			}
		]
	}`
}

func TestValidateRevocationList_Valid(t *testing.T) {
	list, err := ValidateRevocationList([]byte(validRevocationJSON()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list.Revocations))
	}
	e := list.Revocations[0]
	if e.Hash != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("hash = %q", e.Hash)
	}
	if e.RevokedOn != "2025-03-15" {
		t.Errorf("revoked_on = %q", e.RevokedOn)
	}
}

func TestValidateRevocationList_Empty(t *testing.T) {
	list, err := ValidateRevocationList([]byte(`{"revocations": []}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Revocations) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(list.Revocations))
	}
}

func TestValidateRevocationList_NonObject(t *testing.T) {
	tests := []string{`[]`, `"hello"`, `123`, `true`}
	for _, input := range tests {
		_, err := ValidateRevocationList([]byte(input))
		if err == nil || err.Error() != "revocation list must be a plain object" {
			t.Errorf("input %s: expected plain object error, got %v", input, err)
		}
	}
}

func TestValidateRevocationList_MissingRevocations(t *testing.T) {
	_, err := ValidateRevocationList([]byte(`{}`))
	if err == nil || err.Error() != "missing required field: revocations" {
		t.Fatalf("expected missing revocations error, got %v", err)
	}
}

func TestValidateRevocationList_RevocationsNotArray(t *testing.T) {
	_, err := ValidateRevocationList([]byte(`{"revocations": "not array"}`))
	if err == nil || err.Error() != "revocations must be an array" {
		t.Fatalf("expected array error, got %v", err)
	}
}

func TestValidateRevocationList_ExtraTopLevelField(t *testing.T) {
	_, err := ValidateRevocationList([]byte(`{"revocations": [], "extra": true}`))
	if err == nil || err.Error() != "unexpected field: extra" {
		t.Fatalf("expected unexpected field error, got %v", err)
	}
}

func TestValidateRevocationList_EntryMissingHash(t *testing.T) {
	data := `{"revocations": [{"revoked_on": "2025-01-01"}]}`
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: hash") {
		t.Fatalf("expected missing hash error, got %v", err)
	}
}

func TestValidateRevocationList_EntryMissingRevokedOn(t *testing.T) {
	data := `{"revocations": [{"hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}]}`
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "missing required field: revoked_on") {
		t.Fatalf("expected missing revoked_on error, got %v", err)
	}
}

func TestValidateRevocationList_EntryExtraField(t *testing.T) {
	data := `{"revocations": [{"hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "revoked_on": "2025-01-01", "extra": "x"}]}`
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "unexpected field: extra") {
		t.Fatalf("expected unexpected field error, got %v", err)
	}
}

func TestValidateRevocationList_HashNotString(t *testing.T) {
	data := `{"revocations": [{"hash": 123, "revoked_on": "2025-01-01"}]}`
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "hash must be a string") {
		t.Fatalf("expected string error, got %v", err)
	}
}

func TestValidateRevocationList_HashTooShort(t *testing.T) {
	// 63 hex chars
	hash := strings.Repeat("a", 63)
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": "2025-01-01"}]}`, hash)
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "64-character hex string") {
		t.Fatalf("expected 64-char hex error for 63 chars, got %v", err)
	}
}

func TestValidateRevocationList_HashTooLong(t *testing.T) {
	// 65 hex chars
	hash := strings.Repeat("a", 65)
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": "2025-01-01"}]}`, hash)
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "64-character hex string") {
		t.Fatalf("expected 64-char hex error for 65 chars, got %v", err)
	}
}

func TestValidateRevocationList_HashNonHex(t *testing.T) {
	// 64 chars but contains 'g'
	hash := strings.Repeat("g", 64)
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": "2025-01-01"}]}`, hash)
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "64-character hex string") {
		t.Fatalf("expected hex error, got %v", err)
	}
}

func TestValidateRevocationList_HashUppercaseNormalized(t *testing.T) {
	hash := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": "2025-01-01"}]}`, hash)
	list, err := ValidateRevocationList([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := strings.ToLower(hash)
	if list.Revocations[0].Hash != expected {
		t.Errorf("hash not normalized: got %q, want %q", list.Revocations[0].Hash, expected)
	}
}

func TestValidateRevocationList_RevokedOnInvalidDate(t *testing.T) {
	hash := strings.Repeat("a", 64)
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": "2025-02-30"}]}`, hash)
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "invalid date for revoked_on") {
		t.Fatalf("expected invalid date error, got %v", err)
	}
}

func TestValidateRevocationList_RevokedOnNotString(t *testing.T) {
	hash := strings.Repeat("a", 64)
	data := fmt.Sprintf(`{"revocations": [{"hash": "%s", "revoked_on": 20250101}]}`, hash)
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "revoked_on must be a string") {
		t.Fatalf("expected string error, got %v", err)
	}
}

func TestValidateRevocationList_TooManyEntries(t *testing.T) {
	hash := strings.Repeat("a", 64)
	entry := fmt.Sprintf(`{"hash": "%s", "revoked_on": "2025-01-01"}`, hash)
	count := MaxRevocationEntries + 1
	entries := make([]string, count)
	for i := range entries {
		entries[i] = entry
	}
	data := `{"revocations": [` + strings.Join(entries, ",") + `]}`
	_, err := ValidateRevocationList([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "exceeding maximum") {
		t.Fatalf("expected exceeding maximum error, got %v", err)
	}
}

func TestValidateRevocationList_ExactlyMaxEntries(t *testing.T) {
	// Each entry needs a unique hash for dedup not to shrink the list.
	entries := make([]string, MaxRevocationEntries)
	for i := range entries {
		hash := fmt.Sprintf("%064x", i)
		entries[i] = fmt.Sprintf(`{"hash": "%s", "revoked_on": "2025-01-01"}`, hash)
	}
	data := `{"revocations": [` + strings.Join(entries, ",") + `]}`
	list, err := ValidateRevocationList([]byte(data))
	if err != nil {
		t.Fatalf("expected no error for %d entries, got %v", MaxRevocationEntries, err)
	}
	if len(list.Revocations) != MaxRevocationEntries {
		t.Errorf("expected %d entries, got %d", MaxRevocationEntries, len(list.Revocations))
	}
}

func TestValidateRevocationList_DuplicateHashDedup(t *testing.T) {
	hash := strings.Repeat("a", 64)
	data := fmt.Sprintf(`{"revocations": [
		{"hash": "%s", "revoked_on": "2025-01-01"},
		{"hash": "%s", "revoked_on": "2025-06-15"}
	]}`, hash, hash)
	list, err := ValidateRevocationList([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("expected 1 entry after dedup, got %d", len(list.Revocations))
	}
	// Should keep first occurrence.
	if list.Revocations[0].RevokedOn != "2025-01-01" {
		t.Errorf("expected first occurrence (2025-01-01), got %s", list.Revocations[0].RevokedOn)
	}
}

func TestIsRevoked_Found(t *testing.T) {
	hash := strings.Repeat("a", 64)
	list := &RevocationList{
		Revocations: []RevocationEntry{{Hash: hash, RevokedOn: "2025-01-01"}},
	}
	set := BuildRevocationSet(list)
	if !IsRevoked(hash, set) {
		t.Error("expected IsRevoked to return true")
	}
}

func TestIsRevoked_NotFound(t *testing.T) {
	hash := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	list := &RevocationList{
		Revocations: []RevocationEntry{{Hash: hash, RevokedOn: "2025-01-01"}},
	}
	set := BuildRevocationSet(list)
	if IsRevoked(other, set) {
		t.Error("expected IsRevoked to return false")
	}
}

func TestIsRevoked_CaseInsensitive(t *testing.T) {
	hashLower := strings.Repeat("a", 64)
	hashUpper := strings.Repeat("A", 64)
	list := &RevocationList{
		Revocations: []RevocationEntry{{Hash: hashLower, RevokedOn: "2025-01-01"}},
	}
	set := BuildRevocationSet(list)
	if !IsRevoked(hashUpper, set) {
		t.Error("expected IsRevoked to be case-insensitive")
	}
}

func TestIsRevoked_EmptyList(t *testing.T) {
	list := &RevocationList{Revocations: []RevocationEntry{}}
	set := BuildRevocationSet(list)
	if IsRevoked(strings.Repeat("a", 64), set) {
		t.Error("expected IsRevoked to return false for empty list")
	}
}

func TestIsRevoked_NilList(t *testing.T) {
	if IsRevoked(strings.Repeat("a", 64), nil) {
		t.Error("expected IsRevoked to return false for nil list")
	}
}

func TestBuildRevocationSet_NilList(t *testing.T) {
	set := BuildRevocationSet(nil)
	if set != nil {
		t.Errorf("expected nil map for nil list, got %v", set)
	}
}

func TestBuildRevocationSet_EmptyList(t *testing.T) {
	list := &RevocationList{Revocations: []RevocationEntry{}}
	set := BuildRevocationSet(list)
	if set == nil {
		t.Fatal("expected non-nil map for empty list")
	}
	if len(set) != 0 {
		t.Errorf("expected empty map, got %d entries", len(set))
	}
}

func TestBuildRevocationSet_PopulatedList(t *testing.T) {
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	list := &RevocationList{
		Revocations: []RevocationEntry{
			{Hash: hashA, RevokedOn: "2025-01-01"},
			{Hash: hashB, RevokedOn: "2025-06-15"},
		},
	}
	set := BuildRevocationSet(list)
	if len(set) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(set))
	}
	if !set[hashA] {
		t.Errorf("expected %s in set", hashA)
	}
	if !set[hashB] {
		t.Errorf("expected %s in set", hashB)
	}
}

func TestBuildRevocationSet_LowercasesHashes(t *testing.T) {
	hashUpper := "AABBCCDD" + strings.Repeat("0", 56)
	hashLower := strings.ToLower(hashUpper)
	list := &RevocationList{
		Revocations: []RevocationEntry{
			{Hash: hashUpper, RevokedOn: "2025-01-01"},
		},
	}
	set := BuildRevocationSet(list)
	if !set[hashLower] {
		t.Errorf("expected lowercase key %s in set", hashLower)
	}
	if set[hashUpper] {
		t.Error("did not expect uppercase key in set")
	}
}

func TestIsRevoked_ViaSet(t *testing.T) {
	hashLower := strings.Repeat("c", 64)
	list := &RevocationList{
		Revocations: []RevocationEntry{
			{Hash: hashLower, RevokedOn: "2025-03-01"},
		},
	}
	set := BuildRevocationSet(list)

	// Mixed-case lookup should match.
	mixedCase := strings.Repeat("C", 32) + strings.Repeat("c", 32)
	if !IsRevoked(mixedCase, set) {
		t.Error("expected IsRevoked to find mixed-case hash in set")
	}

	// Non-existent hash should not match.
	absent := strings.Repeat("d", 64)
	if IsRevoked(absent, set) {
		t.Error("expected IsRevoked to return false for absent hash")
	}
}
