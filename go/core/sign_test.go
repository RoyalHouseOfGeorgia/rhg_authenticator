package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// mockAdapter signs with an in-memory Ed25519 key.
type mockAdapter struct {
	secretKey ed25519.PrivateKey
}

func (m *mockAdapter) ExportPublicKey() ([32]byte, error) {
	var key [32]byte
	copy(key[:], m.secretKey.Public().(ed25519.PublicKey))
	return key, nil
}

func (m *mockAdapter) SignBytes(data []byte) ([]byte, error) {
	return ed25519.Sign(m.secretKey, data), nil
}

// badLengthAdapter returns a signature with the wrong number of bytes.
type badLengthAdapter struct {
	mockAdapter
}

func (m *badLengthAdapter) SignBytes(data []byte) ([]byte, error) {
	return make([]byte, 48), nil
}

// garbageAdapter returns 64 garbage bytes that won't verify.
type garbageAdapter struct {
	mockAdapter
}

func (m *garbageAdapter) SignBytes(data []byte) ([]byte, error) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = 0xff
	}
	return sig, nil
}

// errorAdapter returns an error from SignBytes.
type errorAdapter struct {
	mockAdapter
}

func (m *errorAdapter) SignBytes(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("hardware device error")
}

// testSecretKey returns the deterministic key matching the test vectors:
// first byte 0x01, rest zeros.
func testSecretKey() ed25519.PrivateKey {
	seed := make([]byte, 32)
	seed[0] = 0x01
	return ed25519.NewKeyFromSeed(seed)
}

func testPubKey() [32]byte {
	sk := testSecretKey()
	var pub [32]byte
	copy(pub[:], sk.Public().(ed25519.PublicKey))
	return pub
}

// testVector matches the JSON structure from the TypeScript generator.
type testVector struct {
	Name       string         `json:"name"`
	Credential map[string]any `json:"credential"`
	CanonHex   string         `json:"canonical_hex"`
	PayloadB64 string         `json:"payload_b64url"`
	SigB64     string         `json:"signature_b64url"`
	URL        string         `json:"url"`
	PubKeyHex  string         `json:"public_key_hex"`
}

// Tests must be run from the go/ directory (which 'go test ./...' does by default).
func loadVectors(t *testing.T) []testVector {
	t.Helper()
	data, err := os.ReadFile("../testdata/vectors.json")
	if err != nil {
		t.Fatalf("failed to read vectors.json: %v", err)
	}
	var vectors []testVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse vectors.json: %v", err)
	}
	return vectors
}

func TestCrossLanguageVectors(t *testing.T) {
	vectors := loadVectors(t)
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	pubHex := hex.EncodeToString(pubKey[:])

	for _, vec := range vectors {
		t.Run(vec.Name, func(t *testing.T) {
			// Verify this vector's public key matches the signing key.
			if pubHex != vec.PubKeyHex {
				t.Fatalf("public key mismatch: got %s, want %s", pubHex, vec.PubKeyHex)
			}

			// Reconstruct the credential map with the same types Go would use.
			cred := vec.Credential

			// Canonicalize and check hex.
			canonical, err := Canonicalize(cred)
			if err != nil {
				t.Fatalf("Canonicalize error: %v", err)
			}
			gotHex := hex.EncodeToString(canonical)
			if gotHex != vec.CanonHex {
				t.Errorf("canonical hex mismatch:\n  got  %s\n  want %s", gotHex, vec.CanonHex)
			}

			// Base64URL encode and check.
			gotB64 := Encode(canonical)
			if gotB64 != vec.PayloadB64 {
				t.Errorf("payload b64url mismatch:\n  got  %s\n  want %s", gotB64, vec.PayloadB64)
			}

			// Full HandleSign and check URL.
			recipient, _ := cred["recipient"].(string)
			honor, _ := cred["honor"].(string)
			detail, _ := cred["detail"].(string)
			date, _ := cred["date"].(string)

			resp, err := HandleSign(SignRequest{
				Recipient: recipient,
				Honor:     honor,
				Detail:    detail,
				Date:      date,
			}, adapter, pubKey)
			if err != nil {
				t.Fatalf("HandleSign error: %v", err)
			}
			if resp.URL != vec.URL {
				t.Errorf("URL mismatch:\n  got  %s\n  want %s", resp.URL, vec.URL)
			}
			if resp.Signature != vec.SigB64 {
				t.Errorf("signature mismatch:\n  got  %s\n  want %s", resp.Signature, vec.SigB64)
			}
			if resp.Payload != vec.PayloadB64 {
				t.Errorf("payload mismatch:\n  got  %s\n  want %s", resp.Payload, vec.PayloadB64)
			}
		})
	}
}

func TestHandleSign_ValidationError(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	_, err := HandleSign(SignRequest{
		Recipient: "",
		Honor:     "Test Honor",
		Detail:    "Test Detail",
		Date:      "2026-03-13",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error for empty recipient")
	}
	if !strings.Contains(err.Error(), "invalid credential data") {
		t.Errorf("expected 'Invalid credential data' in error, got: %v", err)
	}
}

func TestHandleSign_PayloadTooLarge(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	// Create a detail field large enough to exceed MaxPayloadBytes.
	hugeDetail := strings.Repeat("x", 2000)

	_, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    hugeDetail,
		Date:      "2026-03-13",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
	if !strings.Contains(err.Error(), "payload exceeds maximum size") {
		t.Errorf("expected 'Payload exceeds maximum size' in error, got: %v", err)
	}
}

// TestHandleSign_PayloadSizeBoundary pins the exact `len > MaxPayloadBytes`
// (strict) boundary: a canonical payload of exactly MaxPayloadBytes must sign,
// MaxPayloadBytes+1 must fail. Landing exactly on the boundary is the only form
// that distinguishes `>` from `>=`. The payload is sized by padding `detail`
// with single-byte ASCII (no JSON escaping, no NFC change), so canonical length
// scales 1:1 with the pad.
func TestHandleSign_PayloadSizeBoundary(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	buildCred := func(detail string) map[string]any {
		return map[string]any{
			"version":   float64(1),
			"recipient": "John Doe",
			"honor":     "Test Honor",
			"detail":    detail,
			"date":      "2026-03-13",
		}
	}

	// Measure canonical overhead with an empty detail, then pad to the limit.
	base, err := Canonicalize(buildCred(""))
	if err != nil {
		t.Fatalf("Canonicalize(baseline) error: %v", err)
	}
	pad := MaxPayloadBytes - len(base)
	if pad <= 0 {
		t.Fatalf("baseline canonical length %d leaves no room to pad to %d", len(base), MaxPayloadBytes)
	}
	atLimitDetail := strings.Repeat("x", pad)

	// Sanity-check the realized canonical length is exactly MaxPayloadBytes
	// before relying on the pass/fail assertions below.
	atLimit, err := Canonicalize(buildCred(atLimitDetail))
	if err != nil {
		t.Fatalf("Canonicalize(at-limit) error: %v", err)
	}
	if len(atLimit) != MaxPayloadBytes {
		t.Fatalf("expected canonical length exactly %d, got %d", MaxPayloadBytes, len(atLimit))
	}

	// Exactly MaxPayloadBytes must sign (check is strict `>`).
	if _, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    atLimitDetail,
		Date:      "2026-03-13",
	}, adapter, pubKey); err != nil {
		t.Errorf("payload of exactly MaxPayloadBytes (%d) should sign, got error: %v", MaxPayloadBytes, err)
	}

	// One byte over must fail with the size error specifically.
	_, err = HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    atLimitDetail + "x",
		Date:      "2026-03-13",
	}, adapter, pubKey)
	if err == nil {
		t.Fatal("payload of MaxPayloadBytes+1 should fail")
	}
	if !strings.Contains(err.Error(), "payload exceeds maximum size") {
		t.Errorf("expected 'payload exceeds maximum size', got: %v", err)
	}
}

func TestHandleSign_SignatureWrongLength(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &badLengthAdapter{mockAdapter{secretKey: sk}}

	_, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "2026-03-13",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}
	if !strings.Contains(err.Error(), "expected 64-byte Ed25519 signature, got 48 bytes") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHandleSign_PostSignVerifyFailure(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &garbageAdapter{mockAdapter{secretKey: sk}}

	_, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "2026-03-13",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error for post-sign verification failure")
	}
	if !strings.Contains(err.Error(), "post-sign verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHandleSign_NFCNormalization(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	// Pass NFD input (e + combining acute = é in NFD).
	resp, err := HandleSign(SignRequest{
		Recipient: "Caf\u0065\u0301", // NFD
		Honor:     "Test Honor",
		Detail:    "re\u0301sume\u0301", // NFD
		Date:      "2026-03-13",
	}, adapter, pubKey)
	if err != nil {
		t.Fatalf("HandleSign error: %v", err)
	}

	// The URL should contain NFC-normalized payload, matching the nfc_edge_case vector.
	vectors := loadVectors(t)
	var nfcVec testVector
	for _, v := range vectors {
		if v.Name == "nfc_edge_case" {
			nfcVec = v
			break
		}
	}
	if nfcVec.Name == "" {
		t.Fatal("nfc_edge_case vector not found")
	}

	if resp.URL != nfcVec.URL {
		t.Errorf("NFC normalization URL mismatch:\n  got  %s\n  want %s", resp.URL, nfcVec.URL)
	}
}

// TestHandleSign_NFCIdempotent verifies that signing an already-NFC input is a
// pure pass-through: deterministic across calls AND leaving the input bytes
// unchanged (not merely deterministically mangled). Distinct from
// TestHandleSign_NFCNormalization, which exercises the NFD->NFC conversion.
func TestHandleSign_NFCIdempotent(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	// Precomposed é (U+00E9) — already NFC, so NFC(x) == x.
	req := SignRequest{
		Recipient: "Café",
		Honor:     "Test Honor",
		Detail:    "résumé",
		Date:      "2026-03-13",
	}

	resp1, err := HandleSign(req, adapter, pubKey)
	if err != nil {
		t.Fatalf("HandleSign (first) error: %v", err)
	}
	resp2, err := HandleSign(req, adapter, pubKey)
	if err != nil {
		t.Fatalf("HandleSign (second) error: %v", err)
	}
	if resp1.Payload != resp2.Payload {
		t.Errorf("payload not deterministic across calls:\n  first  %s\n  second %s", resp1.Payload, resp2.Payload)
	}

	// Decode the payload and confirm normalization left the already-NFC fields
	// byte-for-byte unchanged.
	raw, err := Decode(resp1.Payload)
	if err != nil {
		t.Fatalf("Decode payload error: %v", err)
	}
	var cred map[string]any
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("Unmarshal payload error: %v", err)
	}
	if got, _ := cred["recipient"].(string); got != req.Recipient {
		t.Errorf("recipient changed by normalization: got %q, want %q", got, req.Recipient)
	}
	if got, _ := cred["detail"].(string); got != req.Detail {
		t.Errorf("detail changed by normalization: got %q, want %q", got, req.Detail)
	}
	if got, _ := cred["honor"].(string); got != req.Honor {
		t.Errorf("honor changed by normalization: got %q, want %q", got, req.Honor)
	}
}

func TestHandleSign_SigningAdapterError(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &errorAdapter{mockAdapter{secretKey: sk}}

	_, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "2026-03-13",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error from adapter")
	}
	if !strings.Contains(err.Error(), "signing failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHandleSign_InvalidDate(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	_, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "not-a-date",
	}, adapter, pubKey)

	if err == nil {
		t.Fatal("expected error for invalid date")
	}
	if !strings.Contains(err.Error(), "invalid credential data") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHandleSign_PayloadSHA256Populated(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	resp, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "2026-03-13",
	}, adapter, pubKey)
	if err != nil {
		t.Fatalf("HandleSign error: %v", err)
	}

	// Verify PayloadSHA256 is a 64-char hex string.
	if len(resp.PayloadSHA256) != 64 {
		t.Errorf("PayloadSHA256 length = %d, want 64", len(resp.PayloadSHA256))
	}
	if _, err := hex.DecodeString(resp.PayloadSHA256); err != nil {
		t.Errorf("PayloadSHA256 is not valid hex: %v", err)
	}
}

func TestHandleSign_PayloadSHA256MatchesCanonical(t *testing.T) {
	sk := testSecretKey()
	pubKey := testPubKey()
	adapter := &mockAdapter{secretKey: sk}

	resp, err := HandleSign(SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    "For service",
		Date:      "2026-03-13",
	}, adapter, pubKey)
	if err != nil {
		t.Fatalf("HandleSign error: %v", err)
	}

	// Independently compute SHA-256 from the payload by decoding the base64url payload.
	payloadBytes, err := Decode(resp.Payload)
	if err != nil {
		t.Fatalf("Decode payload error: %v", err)
	}
	expectedHash := sha256.Sum256(payloadBytes)
	expectedHex := hex.EncodeToString(expectedHash[:])

	if resp.PayloadSHA256 != expectedHex {
		t.Errorf("PayloadSHA256 mismatch:\n  got  %s\n  want %s", resp.PayloadSHA256, expectedHex)
	}
}

func TestSignConstants(t *testing.T) {
	if VerifyBaseURL != "https://verify.royalhouseofgeorgia.ge/" {
		t.Errorf("VerifyBaseURL = %q", VerifyBaseURL)
	}
	if MaxPayloadBytes != 2048 {
		t.Errorf("MaxPayloadBytes = %d", MaxPayloadBytes)
	}
}
