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

// ErrInvalidCredential matches (via errors.Is) an *InvalidCredentialError.
var ErrInvalidCredential = errors.New("invalid credential data")

// InvalidCredentialError reports credential fields that failed validation or
// canonicalization. Reason is the operator-facing cause (e.g. "detail exceeds
// maximum length of 2000").
type InvalidCredentialError struct {
	Reason error
}

func (e *InvalidCredentialError) Error() string {
	if e.Reason == nil {
		return ErrInvalidCredential.Error()
	}
	return ErrInvalidCredential.Error() + ": " + e.Reason.Error()
}

// Unwrap returns the underlying validation error.
func (e *InvalidCredentialError) Unwrap() error { return e.Reason }

// Is reports whether target is ErrInvalidCredential.
func (e *InvalidCredentialError) Is(target error) bool { return target == ErrInvalidCredential }

// ErrTooLongForQR matches (via errors.Is) a *TooLongForQRError.
var ErrTooLongForQR = errors.New("too long to fit in a QR code")

// TooLongForQRError reports how far a credential exceeds the QR capacity.
// OverBytes approximates the number of UTF-8 bytes of credential text that
// must be removed (each base64url character carries 3/4 of a byte).
type TooLongForQRError struct {
	OverBytes int
}

// Error is the operator-facing message, shown as-is by Bulk Sign and
// capitalized by the Sign tab, e.g. "too long to fit in a QR code by about 4
// letters (about 2 in Georgian script) — shorten the detail or recipient".
// Georgian letters take three UTF-8 bytes, so that count is OverBytes/3
// rounded up.
func (e *TooLongForQRError) Error() string {
	n := e.OverBytes
	unit := "letters"
	if n == 1 {
		unit = "letter"
	}
	return fmt.Sprintf("%s by about %d %s (about %d in Georgian script) — shorten the detail or recipient",
		ErrTooLongForQR.Error(), n, unit, (n+2)/3)
}

// Is reports whether target is ErrTooLongForQR.
func (e *TooLongForQRError) Is(target error) bool { return target == ErrTooLongForQR }

// overBytes converts a URL length over MaxVerifyURLLength into the number of
// payload bytes to remove: ceil(excess base64url chars × 3/4).
func overBytes(urlLen int) int {
	return ((urlLen-MaxVerifyURLLength)*3 + 3) / 4
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
		return nil, &InvalidCredentialError{Reason: err}
	}

	// 3. Canonicalize.
	payloadBytes, err := Canonicalize(credObj)
	if err != nil {
		return nil, &InvalidCredentialError{Reason: err}
	}

	// 4. QR capacity check: the verification URL must fit a printable QR code.
	if n := VerifyURLLength(payloadBytes); n > MaxVerifyURLLength {
		return nil, &TooLongForQRError{OverBytes: overBytes(n)}
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
