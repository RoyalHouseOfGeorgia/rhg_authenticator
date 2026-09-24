package gui

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// SignFlowPhase identifies a step in the signing flow for error classification.
type SignFlowPhase string

const (
	PhaseExportKey SignFlowPhase = "export_key"
	PhaseSign      SignFlowPhase = "sign"
	PhaseQR        SignFlowPhase = "qr"
	PhaseLog       SignFlowPhase = "log"
)

// SignFlowError wraps an error with the phase it occurred in.
type SignFlowError struct {
	Phase SignFlowPhase
	Err   error
}

func (e *SignFlowError) Error() string { return string(e.Phase) + ": " + e.Err.Error() }
func (e *SignFlowError) Unwrap() error { return e.Err }

// SignFlowResult holds the output of a successful signing operation.
type SignFlowResult struct {
	Response   core.SignResponse
	PNGPreview []byte
	Hash8      string
}

// signAndLog opens the adapter with a pre-resolved PIN, exports the public
// key, signs, and appends an NFC-normalized issuance record to logPath (skipped
// when logPath is empty).
//
// Adapter-open failures are returned unwrapped; export-key and sign failures
// are wrapped in a *SignFlowError with PhaseExportKey / PhaseSign. If the
// record append fails, the successful SignResponse is returned TOGETHER WITH a
// *SignFlowError{Phase: PhaseLog} wrapping core.ErrNotLogged and the underlying
// append error — callers decide whether an unlogged signature is fatal.
func signAndLog(
	req core.SignRequest,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	pin string,
	logger *debuglog.Logger,
) (core.SignResponse, error) {
	// Open adapter with the pre-resolved PIN; piv-go's PINPrompt returns it
	// instantly. This assumes a fresh per-sign Open/Close (the production
	// openAdapter builds a new adapter each call) — a long-lived adapter would
	// reintroduce the whole-app held transaction this ordering avoids.
	adapter, closer, err := openAdapter(func() (string, error) { return pin, nil })
	if err != nil {
		logger.Log("connect: " + core.SanitizeForLog(err.Error()))
		return core.SignResponse{}, err
	}
	defer closer.Close()

	pubKey, err := adapter.ExportPublicKey()
	if err != nil {
		logger.Log(sanitizeError("ExportPublicKey", err))
		return core.SignResponse{}, &SignFlowError{Phase: PhaseExportKey, Err: err}
	}

	resp, err := core.HandleSign(req, adapter, pubKey)
	if err != nil {
		logger.Log(sanitizeError("HandleSign", err))
		return core.SignResponse{}, &SignFlowError{Phase: PhaseSign, Err: err}
	}

	// Build issuance record from request + response fields.
	// NFC-normalize to match what HandleSign signed (raw req fields may differ).
	record := issuancelog.IssuanceRecord{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Recipient:       norm.NFC.String(req.Recipient),
		Honor:           norm.NFC.String(req.Honor),
		Detail:          norm.NFC.String(req.Detail),
		Date:            req.Date,
		PayloadSHA256:   resp.PayloadSHA256,
		SignatureB64URL: resp.Signature,
	}

	if logPath != "" {
		if logErr := issuancelog.AppendRecord(logPath, record); logErr != nil {
			logger.Log("log append failed: " + core.SanitizeForLog(logErr.Error()))
			return resp, &SignFlowError{Phase: PhaseLog, Err: fmt.Errorf("%w: %w", core.ErrNotLogged, logErr)}
		}
	}

	return resp, nil
}

// executeSignFlow runs the signing workflow: resolve PIN, open adapter, export
// key, sign, log, generate QR, compute hash8.
func executeSignFlow(
	req core.SignRequest,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	readPin func() (string, error),
	onConnecting func(),
	logger *debuglog.Logger,
) (SignFlowResult, error) {
	// 1. Resolve the PIN up-front, BEFORE opening the card. piv-go holds an
	//    exclusive PCSC transaction (SCARD_SHARE_EXCLUSIVE + an open transaction)
	//    for the whole connection lifetime, and its lazy PINPrompt fires inside
	//    that transaction. Prompting for the PIN after Open would hold the
	//    exclusive transaction open across human PIN entry, inviting a PC/SC
	//    card reset on the subsequent VERIFY/sign APDU. Resolving first shrinks
	//    the held-transaction window to cert-read + login + sign.
	pin, err := readPin()
	if err != nil {
		// ErrSigningCancelled / ErrPINEntryTimedOut / ErrPINCacheUnavailable are
		// surfaced as-is; signFlowErrorMessage maps them via errors.Is.
		return SignFlowResult{}, err
	}

	if onConnecting != nil {
		onConnecting()
	}

	// 2. Open (fresh per sign, with the pre-resolved PIN), export key, sign,
	//    and append the issuance record.
	resp, err := signAndLog(req, logPath, openAdapter, pin, logger)
	if err != nil && !errors.Is(err, core.ErrNotLogged) {
		return SignFlowResult{}, err
	}
	// A log-append failure is non-fatal for single-sign: the credential is
	// already signed and signAndLog has recorded the failure in the debug log.

	// 3. Generate QR preview.
	pngData, err := qr.GeneratePNG(resp.URL, qrPreviewPx)
	if err != nil {
		logger.Log(sanitizeError("QR", err))
		return SignFlowResult{}, &SignFlowError{Phase: PhaseQR, Err: err}
	}

	// 4. First 8 hex chars of the SHA-256 hash, used as a short identifier in filenames.
	hash8 := resp.PayloadSHA256[:8]

	return SignFlowResult{
		Response:   resp,
		PNGPreview: pngData,
		Hash8:      hash8,
	}, nil
}

// clearPINCacheOnAuthError clears the cached PIN when err is a PIV PIN
// authentication failure. MakePinReader caches the PIN at dialog submission,
// before the YubiKey verifies it; on an authentication failure the cached
// (wrong) PIN must be cleared so it is not silently replayed on retry — each
// replay decrements the PIV retry counter and can lock the applet.
//
// This lives at package level so the behavior is unit-testable without driving
// the Fyne closure. PinCache.Clear() is mutex-protected and callable off the UI
// thread; it invalidates-and-zeroes without flipping the user's "remember"
// preference.
func clearPINCacheOnAuthError(err error, cache *yubikey.PinCache) {
	if err != nil && yubikey.IsPINAuthError(err) {
		cache.Clear()
	}
}
