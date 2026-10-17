package service

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// honorTitles are the available credential honor designations.
var honorTitles = []string{
	"Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ",
	"Order of the St. Queen Tamar of Georgia",
	"Order of the Crown of Georgia",
	"Medal of Merit of the Royal House of Georgia",
	"Ennoblement",
	"Appointment",
	"Other",
}

// QR code output sizes.
const (
	qrPreviewPx = 512
	qrSavePx    = 2048
)

// signFlowPhase identifies a step in the signing flow for error classification.
type signFlowPhase string

const (
	phaseExportKey signFlowPhase = "export_key"
	phaseSign      signFlowPhase = "sign"
	phaseQR        signFlowPhase = "qr"
	phaseLog       signFlowPhase = "log"
)

// signFlowError wraps an error with the phase it occurred in.
type signFlowError struct {
	Phase signFlowPhase
	Err   error
}

func (e *signFlowError) Error() string { return string(e.Phase) + ": " + e.Err.Error() }
func (e *signFlowError) Unwrap() error { return e.Err }

// errIssuanceLogUnreadable indicates the issuance log could not be read or
// parsed, so the duplicate check cannot run. Signing is refused rather than
// risking a duplicate record.
var errIssuanceLogUnreadable = errors.New("issuance log unreadable")

// signFlowResult holds the output of a successful signing operation.
// Existing is true when the response was rebuilt from a previously logged
// issuance instead of a fresh signature; NotLogged when the credential was
// signed but its issuance record could not be appended.
type signFlowResult struct {
	Response   core.SignResponse
	PNGPreview []byte
	Hash8      string
	Existing   bool
	NotLogged  bool
}

// findExistingIssuance looks up payload (from core.BuildPayload) in the
// issuance log at logPath by SHA-256. On a match it rebuilds the SignResponse
// from the logged signature — the same credential and QR as when it was first
// issued (Ed25519 is deterministic per key). The stored signature is not
// re-verified against the registry; a malformed one is skipped as if absent.
//
// An empty logPath never matches. Log read failures wrap
// errIssuanceLogUnreadable.
func findExistingIssuance(payload []byte, logPath string) (core.SignResponse, bool, error) {
	if logPath == "" {
		return core.SignResponse{}, false, nil
	}

	hash := core.PayloadSHA256Hex(payload)

	records, err := issuancelog.ReadLog(logPath)
	if err != nil {
		return core.SignResponse{}, false, fmt.Errorf("%w: %w", errIssuanceLogUnreadable, err)
	}

	for _, rec := range records {
		if !strings.EqualFold(rec.PayloadSHA256, hash) {
			continue
		}
		// A malformed stored signature is never reused; a later valid match
		// or a fresh signature takes its place.
		if !issuancelog.SignatureWellFormed(rec.SignatureB64URL) {
			continue
		}
		payloadB64 := core.Encode(payload)
		return core.SignResponse{
			Signature:     rec.SignatureB64URL,
			Payload:       payloadB64,
			URL:           core.BuildVerifyURL(payloadB64, rec.SignatureB64URL),
			PayloadSHA256: hash,
		}, true, nil
	}

	return core.SignResponse{}, false, nil
}

// signAndLog opens the adapter with a pre-resolved PIN, exports the public
// key, signs, and appends an NFC-normalized issuance record to logPath (skipped
// when logPath is empty).
//
// Adapter-open failures are returned unwrapped; export-key and sign failures
// are wrapped in a *signFlowError with phaseExportKey / phaseSign. If the
// record append fails, the successful SignResponse is returned TOGETHER WITH a
// *signFlowError{Phase: phaseLog} wrapping core.ErrNotLogged and the underlying
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
		return core.SignResponse{}, &signFlowError{Phase: phaseExportKey, Err: err}
	}

	resp, err := core.HandleSign(req, adapter, pubKey)
	if err != nil {
		logger.Log(sanitizeError("HandleSign", err))
		return core.SignResponse{}, &signFlowError{Phase: phaseSign, Err: err}
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
			return resp, &signFlowError{Phase: phaseLog, Err: fmt.Errorf("%w: %w", core.ErrNotLogged, logErr)}
		}
	}

	return resp, nil
}

// executeSignFlow runs the signing workflow: check the issuance log for an
// identical prior issuance, resolve PIN, open adapter, export key, sign, log,
// generate QR, compute hash8.
//
// If the request was already issued, the PIN prompt, card access, signing and
// log append are all skipped; the response is rebuilt from the logged
// signature and returned with Existing set. An unreadable log blocks signing
// (errIssuanceLogUnreadable) since duplicates cannot be ruled out.
func executeSignFlow(
	req core.SignRequest,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	readPin func() (string, error),
	onConnecting func(),
	logger *debuglog.Logger,
) (signFlowResult, error) {
	// 0. Before any PIN prompt or card access: build the payload, which
	//    refuses an invalid or too-long-for-QR request (*core.InvalidCredentialError,
	//    *core.TooLongForQRError), then check the issuance log. A logged
	//    issuance of the same payload is returned as-is (the credential first
	//    issued), so no duplicate record is written.
	payload, err := core.BuildPayload(req)
	if err != nil {
		logger.Log("pre-sign check: " + core.SanitizeForLog(err.Error()))
		return signFlowResult{}, err
	}
	resp, existing, err := findExistingIssuance(payload, logPath)
	if err != nil {
		logger.Log("pre-sign check: " + core.SanitizeForLog(err.Error()))
		return signFlowResult{}, err
	}

	var notLogged bool
	if !existing {
		// 1. Resolve the PIN up-front, BEFORE opening the card. piv-go holds an
		//    exclusive PCSC transaction (SCARD_SHARE_EXCLUSIVE + an open
		//    transaction) for the whole connection lifetime, and its lazy
		//    PINPrompt fires inside that transaction. Prompting for the PIN after
		//    Open would hold the exclusive transaction open across human PIN
		//    entry, inviting a PC/SC card reset on the subsequent VERIFY/sign
		//    APDU. Resolving first shrinks the held-transaction window to
		//    cert-read + login + sign.
		pin, err := readPin()
		if err != nil {
			// errSigningCancelled / errPINEntryTimedOut / errPINCacheUnavailable
			// are surfaced as-is; signFlowErrorMessage maps them via errors.Is.
			return signFlowResult{}, err
		}

		if onConnecting != nil {
			onConnecting()
		}

		// 2. Open (fresh per sign, with the pre-resolved PIN), export key, sign,
		//    and append the issuance record.
		resp, err = signAndLog(req, logPath, openAdapter, pin, logger)
		if err != nil && !errors.Is(err, core.ErrNotLogged) {
			return signFlowResult{}, err
		}
		// A log-append failure is non-fatal for single-sign: the credential is
		// already signed and signAndLog has recorded the failure in the debug
		// log. The result carries it so the operator is told.
		notLogged = err != nil
	}

	// 3. Generate QR preview.
	pngData, err := qr.GeneratePNG(resp.URL, qrPreviewPx)
	if err != nil {
		logger.Log(sanitizeError("QR", err))
		return signFlowResult{}, &signFlowError{Phase: phaseQR, Err: err}
	}

	// 4. First 8 hex chars of the SHA-256 hash, used as a short identifier in filenames.
	hash8 := resp.PayloadSHA256[:8]

	return signFlowResult{
		Response:   resp,
		PNGPreview: pngData,
		Hash8:      hash8,
		Existing:   existing,
		NotLogged:  notLogged,
	}, nil
}

// clearPINCacheOnAuthError clears the cached PIN when err is a PIV PIN
// authentication failure. App.readPIN caches the PIN at dialog submission,
// before the YubiKey verifies it; on an authentication failure the cached
// (wrong) PIN must be cleared so it is not silently replayed on retry — each
// replay decrements the PIV retry counter and can lock the applet.
// PinCache.Clear is goroutine-safe and keeps the remember preference.
func clearPINCacheOnAuthError(err error, cache *yubikey.PinCache) {
	if err != nil && yubikey.IsPINAuthError(err) {
		cache.Clear()
	}
}

// validateSignForm checks that all required sign form fields are filled and valid.
func validateSignForm(recipient, honor, detail, date string) error {
	if strings.TrimSpace(recipient) == "" {
		return fmt.Errorf("recipient is required")
	}
	if honor == "" {
		return fmt.Errorf("honor title must be selected")
	}
	if strings.TrimSpace(detail) == "" {
		return fmt.Errorf("detail is required")
	}
	if !core.IsValidDate(date) {
		return fmt.Errorf("date must be in YYYY-MM-DD format and be a valid calendar date")
	}
	return nil
}

// BuildFilename constructs a default filename for saving QR code output.
// Format: rhg-credential-<date>-<hash8>-<suffix>.<ext>
// where suffix is "min3cm" for SVG and "2048px" for PNG.
func BuildFilename(date, hash8, ext string) string {
	suffix := "min3cm"
	if ext == "png" {
		suffix = "2048px"
	}
	return fmt.Sprintf("rhg-credential-%s-%s-%s.%s", date, hash8, suffix, ext)
}
