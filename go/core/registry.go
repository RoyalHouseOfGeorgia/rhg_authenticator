package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"golang.org/x/text/unicode/norm"
)

// KeyEntry represents a single key in the registry.
type KeyEntry struct {
	Authority string  `json:"authority"`
	From      string  `json:"from"`
	To        *string `json:"to"`
	Algorithm string  `json:"algorithm"`
	PublicKey string  `json:"public_key"`
	Note      string  `json:"note"`
	// Extra holds unknown fields, preserved verbatim for round-trip.
	Extra map[string]json.RawMessage `json:"-"`
}

// Registry holds the array of key entries.
type Registry struct {
	Keys []KeyEntry `json:"keys"`
	// Extra holds unknown top-level fields, preserved verbatim for round-trip.
	Extra map[string]json.RawMessage `json:"-"`
}

// MaxRegistryKeys is the maximum number of key entries allowed in a registry.
// Prevents memory exhaustion from oversized registries (~2 MiB JSON at 1000 entries).
const MaxRegistryKeys = 1000

// SupportedAlgorithm is the only supported key algorithm.
const SupportedAlgorithm = "Ed25519"

// ED25519SpkiPrefix is the 12-byte DER/SPKI header for Ed25519 public keys.
var ED25519SpkiPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00,
}

// registryFields are the known top-level fields; others go into Registry.Extra.
var registryFields = map[string]bool{"keys": true}

// entryFields are the known key entry fields; others go into KeyEntry.Extra.
var entryFields = map[string]bool{
	"authority":  true,
	"from":       true,
	"to":         true,
	"algorithm":  true,
	"public_key": true,
	"note":       true,
}

// ValidateRegistry validates parsed JSON bytes as a key registry.
func ValidateRegistry(data []byte) (Registry, error) {
	// Unmarshal into a raw map; known fields are validated below, unknown ones kept in Extra.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Registry{}, fmt.Errorf("registry must be a plain object")
	}

	// Check for required "keys" field.
	keysRaw, ok := raw["keys"]
	if !ok {
		return Registry{}, fmt.Errorf("missing required field: keys")
	}

	// Unmarshal keys as array of raw messages.
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(keysRaw, &rawEntries); err != nil {
		return Registry{}, fmt.Errorf("keys must be an array")
	}
	if len(rawEntries) == 0 {
		return Registry{}, fmt.Errorf("keys array must not be empty")
	}
	if len(rawEntries) > MaxRegistryKeys {
		return Registry{}, fmt.Errorf("registry has %d keys, exceeding maximum %d", len(rawEntries), MaxRegistryKeys)
	}

	entries := make([]KeyEntry, 0, len(rawEntries))
	for i, rawEntry := range rawEntries {
		entry, err := validateEntry(rawEntry, i)
		if err != nil {
			return Registry{}, err
		}
		entries = append(entries, entry)
	}

	return Registry{Keys: entries, Extra: unknownFields(raw, registryFields)}, nil
}

// unknownFields returns the entries of raw whose keys are not in known, or nil if none.
func unknownFields(raw map[string]json.RawMessage, known map[string]bool) map[string]json.RawMessage {
	var extra map[string]json.RawMessage
	for key, val := range raw {
		if known[key] {
			continue
		}
		if extra == nil {
			extra = make(map[string]json.RawMessage)
		}
		extra[key] = val
	}
	return extra
}

// appendExtra splices extra fields (sorted by key) before the closing brace of
// the non-empty JSON object obj. Returns obj unchanged when extra is empty.
func appendExtra(obj []byte, extra map[string]json.RawMessage) []byte {
	if len(extra) == 0 {
		return obj
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := append([]byte(nil), obj[:len(obj)-1]...)
	for _, k := range keys {
		name, _ := json.Marshal(k) // marshaling a string cannot fail
		out = append(out, ',')
		out = append(out, name...)
		out = append(out, ':')
		out = append(out, extra[k]...)
	}
	return append(out, '}')
}

// MarshalJSON encodes the known fields followed by Extra. Value receiver so it
// applies when a KeyEntry is marshaled by value.
func (e KeyEntry) MarshalJSON() ([]byte, error) {
	type keyEntryAlias KeyEntry
	obj, err := json.Marshal(keyEntryAlias(e))
	if err != nil {
		return nil, err
	}
	return appendExtra(obj, e.Extra), nil
}

// MarshalJSON encodes the known fields followed by Extra. Value receiver so it
// applies when a Registry is marshaled by value.
func (r Registry) MarshalJSON() ([]byte, error) {
	type registryAlias Registry
	obj, err := json.Marshal(registryAlias(r))
	if err != nil {
		return nil, err
	}
	return appendExtra(obj, r.Extra), nil
}

func validateEntry(data json.RawMessage, index int) (KeyEntry, error) {
	// Unmarshal into a raw map; known fields are validated below, unknown ones kept in Extra.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return KeyEntry{}, fmt.Errorf("keys[%d] must be a plain object", index)
	}

	// authority: non-empty string.
	if _, ok := raw["authority"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: authority", index)
	}
	var authority string
	if err := json.Unmarshal(raw["authority"], &authority); err != nil {
		return KeyEntry{}, fmt.Errorf("keys[%d]: authority must be a string", index)
	}
	if authority == "" {
		return KeyEntry{}, fmt.Errorf("keys[%d]: authority must not be empty", index)
	}
	if controlCharRE.MatchString(authority) {
		return KeyEntry{}, fmt.Errorf("keys[%d]: authority contains invalid control characters", index)
	}

	// from: valid date string.
	if _, ok := raw["from"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: from", index)
	}
	var from string
	if err := json.Unmarshal(raw["from"], &from); err != nil {
		return KeyEntry{}, fmt.Errorf("keys[%d]: from must be a string", index)
	}
	if !IsValidDate(from) {
		return KeyEntry{}, fmt.Errorf("keys[%d]: invalid date for from: %s", index, SanitizeForError(from))
	}

	// to: null or valid date string.
	if _, ok := raw["to"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: to", index)
	}
	var to *string
	// Check if it's null.
	if string(raw["to"]) == "null" {
		to = nil
	} else {
		var toStr string
		if err := json.Unmarshal(raw["to"], &toStr); err != nil {
			return KeyEntry{}, fmt.Errorf("keys[%d]: to must be a string or null", index)
		}
		if !IsValidDate(toStr) {
			return KeyEntry{}, fmt.Errorf("keys[%d]: invalid date for to: %s", index, SanitizeForError(toStr))
		}
		to = &toStr
	}

	// Date range validation.
	if to != nil && *to < from {
		return KeyEntry{}, fmt.Errorf("keys[%d]: invalid date range: from (%s) is after to (%s)", index, SanitizeForError(from), SanitizeForError(*to))
	}

	// algorithm: exactly "Ed25519".
	if _, ok := raw["algorithm"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: algorithm", index)
	}
	var algorithm string
	if err := json.Unmarshal(raw["algorithm"], &algorithm); err != nil || algorithm != SupportedAlgorithm {
		return KeyEntry{}, fmt.Errorf("keys[%d]: algorithm must be '%s'", index, SupportedAlgorithm)
	}

	// public_key: non-empty string.
	if _, ok := raw["public_key"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: public_key", index)
	}
	var publicKey string
	if err := json.Unmarshal(raw["public_key"], &publicKey); err != nil {
		return KeyEntry{}, fmt.Errorf("keys[%d]: public_key must be a string", index)
	}
	if publicKey == "" {
		return KeyEntry{}, fmt.Errorf("keys[%d]: public_key must not be empty", index)
	}

	// note: string (can be empty).
	if _, ok := raw["note"]; !ok {
		return KeyEntry{}, fmt.Errorf("keys[%d]: missing required field: note", index)
	}
	var note string
	if err := json.Unmarshal(raw["note"], &note); err != nil {
		return KeyEntry{}, fmt.Errorf("keys[%d]: note must be a string", index)
	}
	if controlCharRE.MatchString(note) {
		return KeyEntry{}, fmt.Errorf("keys[%d]: note contains invalid control characters", index)
	}

	return KeyEntry{
		Authority: norm.NFC.String(authority),
		From:      from,
		To:        to,
		Algorithm: algorithm,
		PublicKey: publicKey,
		Note:      note,
		Extra:     unknownFields(raw, entryFields),
	}, nil
}

// DecodePublicKey decodes a key entry's public_key field to raw 32-byte Ed25519 key material.
// Accepts 44-byte SPKI DER (strips 12-byte prefix) or 32-byte raw.
func DecodePublicKey(entry KeyEntry) ([32]byte, error) {
	var result [32]byte

	if len(entry.PublicKey) > 256 {
		return result, fmt.Errorf("decodePublicKey: public_key exceeds maximum length")
	}

	rawKey, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	if err != nil {
		return result, fmt.Errorf("decodePublicKey: invalid base64: %w", err)
	}

	if len(rawKey) == 44 {
		if !bytes.HasPrefix(rawKey, ED25519SpkiPrefix) {
			return result, fmt.Errorf("decodePublicKey: 44-byte key does not have expected Ed25519 SPKI prefix")
		}
		copy(result[:], rawKey[len(ED25519SpkiPrefix):])
		return result, nil
	}

	if len(rawKey) == 32 {
		copy(result[:], rawKey)
		return result, nil
	}

	return result, fmt.Errorf("decodePublicKey: unexpected key length %d bytes (expected 32 or 44)", len(rawKey))
}

// KeyFingerprint returns the SHA-256 fingerprint of a key entry's public key
// as a hex string. Returns an error if the key cannot be decoded.
func KeyFingerprint(entry KeyEntry) (string, error) {
	raw, err := DecodePublicKey(entry)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw[:])
	return hex.EncodeToString(hash[:]), nil
}

// FindKeysByAuthority returns all key entries matching the given authority.
// Both query and entry authority are NFC-normalized. Comparison is case-sensitive.
func FindKeysByAuthority(reg Registry, authority string) []KeyEntry {
	normalizedQuery := norm.NFC.String(authority)
	var result []KeyEntry
	for _, entry := range reg.Keys {
		// entry.Authority is already NFC-normalized during validation.
		if entry.Authority == normalizedQuery {
			result = append(result, entry)
		}
	}
	return result
}

// IsDateInRange checks if a credential date falls within a key's validity range.
// Only the key's to date applies (inclusive, lexicographic comparison); from is
// informational, so dates before from are in range (backdated honors verify).
// to=nil means no upper bound. Mirrors isDateInRange in src/registry.ts.
// Returns false for malformed dates (callers validate format at input boundaries).
func IsDateInRange(credDate string, key KeyEntry) bool {
	if !dateRE.MatchString(credDate) {
		return false
	}
	if key.To != nil && credDate > *key.To {
		return false
	}
	return true
}
