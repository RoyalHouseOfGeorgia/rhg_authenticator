package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/text/unicode/norm"
)

// VerifyBaseURL is the base URL for credential verification pages.
const VerifyBaseURL = "https://verify.royalhouseofgeorgia.ge/"

// MaxPayloadBytes is the maximum allowed size of the canonical JSON payload.
const MaxPayloadBytes = 2048

// SigningAdapter abstracts hardware signing devices (e.g., YubiKey).
// SignBytes must return exactly 64 bytes (Ed25519 signature) or an error.
// ExportPublicKey returns the cached 32-byte Ed25519 public key.
// Errors from SignBytes are non-recoverable for the current signing operation.
type SigningAdapter interface {
	ExportPublicKey() ([32]byte, error)
	SignBytes(data []byte) ([]byte, error)
}

// SignRequest is the input to HandleSign.
type SignRequest struct {
	Recipient string
	Honor     string
	Detail    string
	Date      string
}

// SignResponse is the successful output of HandleSign.
type SignResponse struct {
	Signature     string // base64url-encoded signature
	Payload       string // base64url-encoded canonical JSON
	URL           string // full verification URL
	PayloadSHA256 string // hex-encoded SHA-256 of raw canonical JSON bytes (pre-base64url)
}

// ErrNotLogged indicates a credential was signed but its issuance record could
// not be appended to the audit log. Callers that require the audit guarantee
// (bulk signing) treat it as fatal; single-sign treats it as non-fatal.
var ErrNotLogged = errors.New("signed but not recorded in audit log")

// BuildPayload NFC-normalizes and validates req, then returns its canonical
// JSON payload bytes. It is the single source of the bytes HandleSign signs.
func BuildPayload(req SignRequest) ([]byte, error) {
	// 1. Construct credential with NFC-normalized fields.
	credObj := map[string]any{
		"version":   float64(1),
		"recipient": norm.NFC.String(req.Recipient),
		"honor":     norm.NFC.String(req.Honor),
		"detail":    norm.NFC.String(req.Detail),
		"date":      req.Date,
	}

	// 2. Validate credential.
	if _, err := ValidateCredential(credObj); err != nil {
		return nil, fmt.Errorf("invalid credential data: %w", err)
	}

	// 3. Canonicalize.
	payloadBytes, err := Canonicalize(credObj)
	if err != nil {
		return nil, fmt.Errorf("invalid credential data: %w", err)
	}

	// 4. Size check.
	if len(payloadBytes) > MaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds maximum size")
	}
	return payloadBytes, nil
}

// PayloadSHA256Hex returns the lowercase hex SHA-256 of the raw canonical payload.
func PayloadSHA256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// BuildVerifyURL returns the verification URL for base64url-encoded payload and signature.
func BuildVerifyURL(payloadB64, sigB64 string) string {
	return VerifyBaseURL + "?p=" + payloadB64 + "&s=" + sigB64
}

// HandleSign validates, signs, and produces a verification URL for a credential.
func HandleSign(req SignRequest, adapter SigningAdapter, pubKey [32]byte) (SignResponse, error) {
	payloadBytes, err := BuildPayload(req)
	if err != nil {
		return SignResponse{}, err
	}

	// Sign.
	signature, err := adapter.SignBytes(payloadBytes)
	if err != nil {
		return SignResponse{}, fmt.Errorf("signing failed: %w", err)
	}
	if len(signature) != 64 {
		return SignResponse{}, fmt.Errorf("expected 64-byte Ed25519 signature, got %d bytes", len(signature))
	}

	// Post-sign verification.
	if !ed25519.Verify(pubKey[:], payloadBytes, signature) {
		return SignResponse{}, fmt.Errorf("post-sign verification failed — signature does not verify")
	}

	payloadB64 := Encode(payloadBytes)
	sigB64 := Encode(signature)
	return SignResponse{
		Signature:     sigB64,
		Payload:       payloadB64,
		URL:           BuildVerifyURL(payloadB64, sigB64),
		PayloadSHA256: PayloadSHA256Hex(payloadBytes),
	}, nil
}
