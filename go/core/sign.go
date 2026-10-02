package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// VerifyBaseURL is the base URL for credential verification pages.
const VerifyBaseURL = "https://verify.royalhouseofgeorgia.ge/"

// MaxVerifyURLLength is the longest verification URL that fits a printable QR
// code at error-correction level Q (minimum print size 3 cm). BuildPayload
// refuses credentials whose URL would exceed it, before anything is signed.
const MaxVerifyURLLength = 625

// sigB64Len is the length of a base64url-encoded (unpadded) Ed25519 signature.
var sigB64Len = base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize)

// ErrInvalidCredential indicates the credential fields failed validation or
// canonicalization.
var ErrInvalidCredential = errors.New("invalid credential data")

// ErrTooLongForQR indicates the credential's verification URL would exceed
// MaxVerifyURLLength. Match with errors.Is; use errors.As with
// *TooLongForQRError for the overage.
var ErrTooLongForQR = errors.New("too long to fit in a QR code")

// TooLongForQRError reports how far a credential exceeds the QR capacity.
// OverBytes approximates the number of UTF-8 bytes of credential text that
// must be removed (each base64url character carries 3/4 of a byte).
type TooLongForQRError struct {
	OverBytes int
}

// Error returns a user-readable message. Georgian letters take 3 bytes in
// UTF-8, so the Georgian estimate is OverBytes/3 rounded up.
func (e *TooLongForQRError) Error() string {
	return "too long to fit in a QR code by " + e.Overage() + " — shorten the detail or recipient"
}

// Overage describes the excess in letters, e.g. "about 4 letters (about 2 in
// Georgian script)". Georgian letters take three UTF-8 bytes, so the Georgian
// count is OverBytes/3 rounded up. "letter" is singular for a count of 1.
func (e *TooLongForQRError) Overage() string {
	n := e.OverBytes
	unit := "letters"
	if n == 1 {
		unit = "letter"
	}
	return fmt.Sprintf("about %d %s (about %d in Georgian script)", n, unit, (n+2)/3)
}

// Is reports whether target is ErrTooLongForQR.
func (e *TooLongForQRError) Is(target error) bool {
	return target == ErrTooLongForQR
}

// VerifyURLLength returns the length of the verification URL that signing
// payload would produce. It is derived from BuildVerifyURL so the two cannot
// drift.
func VerifyURLLength(payload []byte) int {
	return len(BuildVerifyURL(Encode(payload), strings.Repeat("A", sigB64Len)))
}

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
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}

	// 3. Canonicalize.
	payloadBytes, err := Canonicalize(credObj)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}

	// 4. QR capacity check: the verification URL must fit a printable QR code.
	if n := VerifyURLLength(payloadBytes); n > MaxVerifyURLLength {
		return nil, &TooLongForQRError{OverBytes: ((n-MaxVerifyURLLength)*3 + 3) / 4}
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
