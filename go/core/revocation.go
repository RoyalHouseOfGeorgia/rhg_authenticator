package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// RevocationEntry represents a single revoked credential hash.
type RevocationEntry struct {
	Hash      string `json:"hash"`
	RevokedOn string `json:"revoked_on"`
}

// RevocationList holds the array of revocation entries.
type RevocationList struct {
	Revocations []RevocationEntry `json:"revocations"`
}

// MaxRevocationEntries is the maximum number of entries allowed in a revocation list.
const MaxRevocationEntries = 10000

// hexHash64RE matches exactly 64 lowercase hex characters.
var hexHash64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// revocationFields are the only allowed top-level fields.
var revocationFields = map[string]bool{"revocations": true}

// revocationEntryFields are the only allowed fields in a revocation entry.
var revocationEntryFields = map[string]bool{
	"hash":       true,
	"revoked_on": true,
}

// ValidateRevocationList validates parsed JSON bytes as a revocation list.
func ValidateRevocationList(data []byte) (*RevocationList, error) {
	// Unmarshal into raw structure to check fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("revocation list must be a plain object")
	}

	// Check for required "revocations" field.
	revocationsRaw, ok := raw["revocations"]
	if !ok {
		return nil, fmt.Errorf("missing required field: revocations")
	}

	// Reject extra top-level fields.
	for key := range raw {
		if !revocationFields[key] {
			return nil, fmt.Errorf("unexpected field: %s", key)
		}
	}

	// Unmarshal revocations as array of raw messages.
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(revocationsRaw, &rawEntries); err != nil {
		return nil, fmt.Errorf("revocations must be an array")
	}

	// Empty array is valid for revocation lists.
	if len(rawEntries) > MaxRevocationEntries {
		return nil, fmt.Errorf("revocation list has %d entries, exceeding maximum %d", len(rawEntries), MaxRevocationEntries)
	}

	seen := make(map[string]bool, len(rawEntries))
	entries := make([]RevocationEntry, 0, len(rawEntries))
	for i, rawEntry := range rawEntries {
		entry, err := validateRevocationEntry(rawEntry, i)
		if err != nil {
			return nil, err
		}
		// Silently deduplicate by hash (keep first occurrence).
		if seen[entry.Hash] {
			continue
		}
		seen[entry.Hash] = true
		entries = append(entries, entry)
	}

	return &RevocationList{Revocations: entries}, nil
}

func validateRevocationEntry(data json.RawMessage, index int) (RevocationEntry, error) {
	// Unmarshal into map to check fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return RevocationEntry{}, fmt.Errorf("revocations[%d] must be a plain object", index)
	}

	// Reject extra fields.
	for key := range raw {
		if !revocationEntryFields[key] {
			return RevocationEntry{}, fmt.Errorf("revocations[%d]: unexpected field: %s", index, key)
		}
	}

	// hash: required, 64-char hex string.
	if _, ok := raw["hash"]; !ok {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: missing required field: hash", index)
	}
	var hash string
	if err := json.Unmarshal(raw["hash"], &hash); err != nil {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: hash must be a string", index)
	}
	hash = strings.ToLower(hash)
	if !hexHash64RE.MatchString(hash) {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: hash must be a 64-character hex string, got: %s", index, SanitizeForError(hash))
	}

	// revoked_on: required, valid YYYY-MM-DD date.
	if _, ok := raw["revoked_on"]; !ok {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: missing required field: revoked_on", index)
	}
	var revokedOn string
	if err := json.Unmarshal(raw["revoked_on"], &revokedOn); err != nil {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: revoked_on must be a string", index)
	}
	if !IsValidDate(revokedOn) {
		return RevocationEntry{}, fmt.Errorf("revocations[%d]: invalid date for revoked_on: %s", index, SanitizeForError(revokedOn))
	}

	return RevocationEntry{
		Hash:      hash,
		RevokedOn: revokedOn,
	}, nil
}

// BuildRevocationSet returns a map for O(1) revocation lookups.
// Hashes are stored as returned by validation (lowercased), but
// BuildRevocationSet also applies ToLower as defense-in-depth for
// lists not produced by ValidateRevocationList.
// Callers should still normalize lookup keys via strings.ToLower.
func BuildRevocationSet(list *RevocationList) map[string]bool {
	if list == nil {
		return nil
	}
	set := make(map[string]bool, len(list.Revocations))
	for _, entry := range list.Revocations {
		set[strings.ToLower(entry.Hash)] = true
	}
	return set
}

// IsRevoked checks whether a payload hash appears in the revocation set.
// Applies strings.ToLower as defense-in-depth (hashes are already lowercased
// during validation, but callers may pass un-normalized input).
func IsRevoked(payloadHash string, set map[string]bool) bool {
	if set == nil {
		return false
	}
	return set[strings.ToLower(payloadHash)]
}
