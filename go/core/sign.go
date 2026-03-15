package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"golang.org/x/text/unicode/norm"

	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
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

// HandleSign validates, signs, and produces a verification URL for a credential.
func HandleSign(req SignRequest, adapter SigningAdapter, pubKey [32]byte, logPath string) (SignResponse, error) {
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
		return SignResponse{}, fmt.Errorf("invalid credential data: %w", err)
	}

	// 3. Canonicalize.
	payloadBytes, err := Canonicalize(credObj)
	if err != nil {
		return SignResponse{}, fmt.Errorf("invalid credential data: %w", err)
	}

	// 4. Size check.
	if len(payloadBytes) > MaxPayloadBytes {
		return SignResponse{}, fmt.Errorf("payload exceeds maximum size")
	}

	// 5. Sign.
	signature, err := adapter.SignBytes(payloadBytes)
	if err != nil {
		return SignResponse{}, fmt.Errorf("signing failed: %w", err)
	}
	if len(signature) != 64 {
		return SignResponse{}, fmt.Errorf("expected 64-byte Ed25519 signature, got %d bytes", len(signature))
	}

	// 6. Post-sign verification.
	if !ed25519.Verify(pubKey[:], payloadBytes, signature) {
		return SignResponse{}, fmt.Errorf("post-sign verification failed — signature does not verify")
	}

	// 7. Build URL.
	payloadB64 := Encode(payloadBytes)
	sigB64 := Encode(signature)
	url := VerifyBaseURL + "?p=" + payloadB64 + "&s=" + sigB64

	// 8. Append issuance log record (non-fatal — signing already succeeded).
	sha256sum := sha256.Sum256(payloadBytes)
	record := issuancelog.IssuanceRecord{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Recipient:       credObj["recipient"].(string),
		Honor:           credObj["honor"].(string),
		Detail:          credObj["detail"].(string),
		Date:            credObj["date"].(string),
		PayloadSHA256:   hex.EncodeToString(sha256sum[:]),
		SignatureB64URL: sigB64,
	}
	// Fields guaranteed present as strings by ValidateCredential above.
	if logPath != "" {
		if err := issuancelog.AppendRecord(logPath, record); err != nil {
			// Synchronous write is <1ms for expected volume (~100s of records).
			fmt.Fprintf(os.Stderr, "warning: log append failed: %v\n", err)
		}
	}

	// 9. Return response.
	return SignResponse{
		Signature:     sigB64,
		Payload:       payloadB64,
		URL:           url,
		PayloadSHA256: hex.EncodeToString(sha256sum[:]),
	}, nil
}
