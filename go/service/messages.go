package service

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/errorreport"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// sanitizeError returns a generic description for hardware-related errors,
// stripping implementation details that could leak hardware configuration.
func sanitizeError(prefix string, err error) string {
	if err == nil {
		return prefix + ": unknown error"
	}
	switch core.ClassifyHardwareError(err) {
	case core.HwErrSmartcard:
		return prefix + ": smart card service error"
	case core.HwErrPIN:
		return prefix + ": PIN error"
	case core.HwErrTransient:
		return prefix + ": card reset"
	case core.HwErrHardware:
		return prefix + ": hardware device error"
	default:
		return prefix + ": unexpected error"
	}
}

// friendlyYubiKeyError returns a user-friendly error message for YubiKey
// connection failures.
func friendlyYubiKeyError(err error, logger *debuglog.Logger) string {
	if err == nil {
		return "Unknown YubiKey error"
	}
	// Always log the actual error for diagnosis.
	logger.Log("yubikey: " + core.SanitizeForLog(err.Error()))
	switch core.ClassifyHardwareError(err) {
	// SignFlowErrorMessage handles transient card resets upstream and returns before
	// calling this helper, so this case is unreachable via that path. It is kept so the
	// helper's error→message mapping stays complete for any direct or future caller.
	case core.HwErrTransient:
		return core.MsgYubiKeyReset
	case core.HwErrSmartcard:
		return "Smart card service not available. On macOS this is built-in; on Windows check the Smart Card service is running."
	case core.HwErrHardware:
		return "YubiKey not detected. Ensure the key is plugged in."
	default:
		return "Failed to connect to YubiKey. Use Help → Export Error Log… for details."
	}
}

// isOperatorInputError reports whether err is a problem with what the operator
// typed (invalid, or too long for a QR code) rather than a fault.
func isOperatorInputError(err error) bool {
	return errors.Is(err, core.ErrTooLongForQR) || errors.Is(err, core.ErrInvalidCredential)
}

// OfferIssueReport reports whether a sign-flow error warrants a "Report Issue"
// button. Cancellations, benign PIN-entry timeouts, and operator input errors
// are not bugs.
func OfferIssueReport(err error) bool {
	return !errors.Is(err, ErrSigningCancelled) &&
		!errors.Is(err, ErrPINEntryTimedOut) &&
		!isOperatorInputError(err)
}

// SignIssueBody builds the GitHub issue body for a sign-flow error. It carries
// the user-facing msg plus only fixed enum strings (the *SignFlowError phase
// and the core.ClassifyHardwareError category) — never err.Error(), which can
// contain local file paths and smart-card reader names.
func SignIssueBody(err error, msg string) string {
	detail := msg
	var sfe *SignFlowError
	if errors.As(err, &sfe) {
		detail += " (phase: " + string(sfe.Phase) + ")"
	}
	if cat := core.ClassifyHardwareError(err); cat != "" {
		detail += " (hardware: " + cat + ")"
	}
	return errorreport.BuildIssueBody(buildinfo.Version, "signing", detail)
}

// capitalize upper-cases the first letter of s.
func capitalize(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if size == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}

// SignFlowErrorMessage maps an error from ExecuteSignFlow to a user-friendly
// status message.
func SignFlowErrorMessage(err error, logger *debuglog.Logger) string {
	// Operator input errors from BuildPayload come first so their reason text
	// is never misread by the hardware classifier below. The core error text
	// is the message (shared with Bulk Sign), capitalized for the status line.
	var tooLong *core.TooLongForQRError
	if errors.As(err, &tooLong) {
		return capitalize(tooLong.Error()) + "."
	}
	var invalid *core.InvalidCredentialError
	if errors.As(err, &invalid) {
		return capitalize(core.SanitizeForError(invalid.Error())) + "."
	}
	// PIN-flow sentinels are returned bare from readPin (ExecuteSignFlow resolves
	// the PIN before openAdapter, so piv-go never %v-wraps them), matched via
	// errors.Is. These MUST be checked before ClassifyHardwareError, whose \bpin\b
	// regex would otherwise misclassify the timeout/mlock messages as HwErrPIN.
	// This depends on the prompt-before-open ordering in ExecuteSignFlow —
	// reintroducing a lazy PINPrompt would break the errors.Is match.
	if errors.Is(err, ErrSigningCancelled) {
		return ""
	}
	if errors.Is(err, ErrPINEntryTimedOut) {
		return "PIN entry timed out. Click Sign to try again."
	}
	if errors.Is(err, ErrPINCacheUnavailable) {
		return "Could not secure the PIN in memory. Please restart the app."
	}
	// Checked before ClassifyHardwareError for the same reason as ErrNotLogged:
	// the wrapped read/parse error text must not be misread as a hardware fault.
	if errors.Is(err, ErrIssuanceLogUnreadable) {
		return "Could not read the issuance log, so duplicates can't be checked. Signing is blocked until it is readable."
	}
	// Checked before ClassifyHardwareError, whose regex could misread the
	// wrapped OS file error (e.g. a path or errno text) as a hardware fault.
	if errors.Is(err, core.ErrNotLogged) {
		logger.Log(core.SanitizeForLog(err.Error()))
		return "Credential signed but NOT recorded in the audit log — check disk space/permissions."
	}
	// Transient PC/SC contention (card reset) can surface in any phase and via
	// the raw adapter-open path. Hoist the check so it wins over the PIN
	// misclassification even when "verify pin" appears in the wrapped chain.
	cat := core.ClassifyHardwareError(err)
	if cat == core.HwErrTransient {
		logger.Log(core.SanitizeForLog(err.Error()))
		return core.MsgYubiKeyReset
	}
	// Wrong or blocked PIN: give an actionable retry count so the operator does
	// not drain the PIV counter by re-entering the same wrong PIN. Typed check
	// (errors.As on piv.AuthErr), so a transient reset can never reach it.
	if retries, ok := yubikey.PINRetries(err); ok {
		logger.Log(core.SanitizeForLog(err.Error()))
		if retries > 0 {
			return fmt.Sprintf("Incorrect PIN — %d attempt(s) left before the YubiKey locks.", retries)
		}
		return "Incorrect PIN, or the YubiKey PIV applet is locked. No remaining-attempt count was reported — verify with your YubiKey tool before retrying."
	}
	var sfe *SignFlowError
	if errors.As(err, &sfe) {
		switch sfe.Phase {
		case PhaseExportKey:
			return "Failed to read YubiKey. Use Help → Export Error Log… for details."
		case PhaseQR:
			return "QR generation failed. Use Help → Export Error Log… for details."
		case PhaseSign:
			logger.Log(core.SanitizeForLog(sfe.Error()))
			return "Signing failed. Use Help → Export Error Log… for details."
		default:
			logger.Log(core.SanitizeForLog(sfe.Error()))
			return "Unexpected error. Use Help → Export Error Log… for details."
		}
	}
	// Adapter open failures arrive here (not wrapped in SignFlowError).
	// Check certificate/slot errors first — the YubiKey WAS detected but
	// the slot is empty or has the wrong key type. These errors may also
	// contain "smart card" from piv-go, which would misclassify as
	// HwErrHardware ("YubiKey not detected") if checked later.
	errMsg := err.Error()
	logger.Log("sign flow: " + core.SanitizeForLog(errMsg))
	if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "slot 9c") {
		return "No signing certificate found on YubiKey (PIV slot 9c). Generate an Ed25519 key first."
	}
	if cat != "" {
		return friendlyYubiKeyError(err, logger)
	}
	return "Signing failed. Use Help → Export Error Log… for details."
}
