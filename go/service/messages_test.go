package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
)

// resetErr is the real wrapped error chain seen when a PC/SC card reset
// interrupts a signing operation. It contains BOTH "verify pin" (which the old
// classifier misread as a PIN error) AND the smart-card reset phrase, proving
// the transient path wins.
func resetErr() error {
	return errors.New("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid")
}

// --- validateSignForm tests ---

func TestValidateSignForm_AllValid(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "For service", "2026-03-14")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSignForm_EmptyRecipient(t *testing.T) {
	err := validateSignForm("", honorTitles[0], "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty recipient")
	}
	if err.Error() != "Recipient is required." {
		t.Errorf("error should mention recipient, got: %v", err)
	}
}

func TestValidateSignForm_WhitespaceOnlyRecipient(t *testing.T) {
	err := validateSignForm("   ", honorTitles[0], "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for whitespace-only recipient")
	}
}

func TestValidateSignForm_NoHonorSelected(t *testing.T) {
	err := validateSignForm("John Doe", "", "Detail", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty honor")
	}
	if err.Error() != "Honor title must be selected." {
		t.Errorf("error should mention honor, got: %v", err)
	}
}

func TestValidateSignForm_EmptyDetail(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for empty detail")
	}
	if err.Error() != "Detail is required." {
		t.Errorf("error should mention detail, got: %v", err)
	}
}

func TestValidateSignForm_WhitespaceOnlyDetail(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "  \t ", "2026-03-14")
	if err == nil {
		t.Fatal("expected error for whitespace-only detail")
	}
}

func TestValidateSignForm_InvalidDate_BadFormat(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "not-a-date")
	if err == nil {
		t.Fatal("expected error for invalid date")
	}
	if !strings.Contains(err.Error(), "date") {
		t.Errorf("error should mention date, got: %v", err)
	}
}

func TestValidateSignForm_InvalidDate_Feb30(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "2026-02-30")
	if err == nil {
		t.Fatal("expected error for Feb 30")
	}
}

func TestValidateSignForm_InvalidDate_Empty(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "")
	if err == nil {
		t.Fatal("expected error for empty date")
	}
}

func TestValidateSignForm_ValidLeapYear(t *testing.T) {
	err := validateSignForm("John Doe", honorTitles[0], "Detail", "2024-02-29")
	if err != nil {
		t.Fatalf("unexpected error for valid leap year date: %v", err)
	}
}

// --- buildFilename tests ---

func TestBuildFilename_SVG(t *testing.T) {
	got := buildFilename("2026-03-14", "abcd1234", "svg")
	want := "rhg-credential-2026-03-14-abcd1234-min3cm.svg"
	if got != want {
		t.Errorf("buildFilename SVG = %q, want %q", got, want)
	}
}

func TestBuildFilename_PNG(t *testing.T) {
	got := buildFilename("2026-03-14", "abcd1234", "png")
	want := "rhg-credential-2026-03-14-abcd1234-2048px.png"
	if got != want {
		t.Errorf("buildFilename PNG = %q, want %q", got, want)
	}
}

func TestBuildFilename_OtherExt(t *testing.T) {
	// Non-png extensions should use "min3cm" suffix.
	got := buildFilename("2026-01-01", "deadbeef", "pdf")
	want := "rhg-credential-2026-01-01-deadbeef-min3cm.pdf"
	if got != want {
		t.Errorf("buildFilename other = %q, want %q", got, want)
	}
}

// --- honorTitles constant tests ---

func TestHonorTitles_Count(t *testing.T) {
	if len(honorTitles) != 7 {
		t.Errorf("honorTitles count = %d, want 7", len(honorTitles))
	}
}

func TestHonorTitles_NotEmpty(t *testing.T) {
	for i, title := range honorTitles {
		if strings.TrimSpace(title) == "" {
			t.Errorf("honorTitles[%d] is empty", i)
		}
	}
}

func TestHonorTitles_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, title := range honorTitles {
		if seen[title] {
			t.Errorf("duplicate honor title: %q", title)
		}
		seen[title] = true
	}
}

func TestHonorTitles_Contains_Eagle(t *testing.T) {
	found := false
	for _, title := range honorTitles {
		if strings.Contains(title, "Eagle") {
			found = true
			break
		}
	}
	if !found {
		t.Error("honorTitles should contain the Eagle order")
	}
}

func TestHonorTitles_Contains_Ennoblement(t *testing.T) {
	found := false
	for _, title := range honorTitles {
		if title == "Ennoblement" {
			found = true
			break
		}
	}
	if !found {
		t.Error("honorTitles should contain Ennoblement")
	}
}

// --- sanitizeError tests ---

func TestSanitizeError_PCSC(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("pcsc daemon not running"))
	if got != "test: smart card service error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_SCARD(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("scard: service unavailable"))
	if got != "test: smart card service error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_PIN(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("wrong PIN entered"))
	if got != "test: PIN error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_YubiKey(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("no YubiKey detected"))
	if got != "test: hardware device error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_Card(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("smart card not found"))
	if got != "test: hardware device error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_CardNoFalsePositive(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("discard data"))
	if got != "test: unexpected error" {
		t.Errorf("got %q, want %q", got, "test: unexpected error")
	}
}

func TestSanitizeError_Generic(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf("unexpected failure"))
	if got != "test: unexpected error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_Nil(t *testing.T) {
	got := sanitizeError("test", nil)
	if got != "test: unknown error" {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeError_EmptyMessage(t *testing.T) {
	got := sanitizeError("test", fmt.Errorf(""))
	if got != "test: unexpected error" {
		t.Errorf("got %q, want %q", got, "test: unexpected error")
	}
}

func TestSanitizeError_Transient(t *testing.T) {
	// A card reset must classify as transient ("card reset"), NOT "PIN error",
	// even though "verify pin" appears in the wrapped chain.
	got := sanitizeError("HandleSign", resetErr())
	if !strings.HasSuffix(got, ": card reset") {
		t.Errorf("got %q, want suffix %q", got, ": card reset")
	}
	if strings.HasSuffix(got, ": PIN error") {
		t.Errorf("transient error misclassified as PIN error: %q", got)
	}
}

// --- friendlyYubiKeyError tests ---

func TestFriendlyYubiKeyError_YubiKeyError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("no YubiKey detected"))
	if !strings.Contains(got, "not detected") {
		t.Errorf("expected 'not detected' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_CardError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("smart card not found"))
	if !strings.Contains(got, "not detected") {
		t.Errorf("expected 'not detected' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_PCSCError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("pcsc daemon not running"))
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_SCARDError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("scard: service not available"))
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected 'Smart card service' message, got: %q", got)
	}
}

func TestFriendlyYubiKeyError_GenericError(t *testing.T) {
	got := friendlyYubiKeyError(fmt.Errorf("unexpected failure"))
	if !strings.Contains(got, "Failed to connect") {
		t.Errorf("expected 'Failed to connect' message, got: %q", got)
	}
	if !strings.HasSuffix(got, "Export the error log for details.") {
		t.Errorf("expected error log export reference in message, got: %q", got)
	}
}

// --- signFlowErrorMessage tests ---

func TestSignFlowErrorMessage_ExportPublicKey(t *testing.T) {
	err := &signFlowError{Phase: phaseExportKey, Err: fmt.Errorf("hardware failure")}
	got := signFlowErrorMessage(err, nil)
	if !strings.Contains(got, "Failed to read YubiKey") {
		t.Errorf("expected YubiKey read failure message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_QRGeneration(t *testing.T) {
	err := &signFlowError{Phase: phaseQR, Err: fmt.Errorf("encode failed")}
	got := signFlowErrorMessage(err, nil)
	if !strings.Contains(got, "QR generation failed") {
		t.Errorf("expected QR failure message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_YubiKeyAdapter(t *testing.T) {
	got := signFlowErrorMessage(fmt.Errorf("pcsc daemon not running"), nil)
	if !strings.Contains(got, "Smart card service") {
		t.Errorf("expected smart card service message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_SignError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	sfe := &signFlowError{Phase: phaseSign, Err: fmt.Errorf("hardware fault")}
	got := signFlowErrorMessage(sfe, logger)
	if !strings.Contains(got, "Signing failed") {
		t.Errorf("expected 'Signing failed' message, got: %q", got)
	}
	// Verify the raw error is logged.
	data, err := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if err != nil {
		t.Fatalf("debug log not created: %v", err)
	}
	if !strings.Contains(string(data), "sign: hardware fault") {
		t.Errorf("debug log should contain raw error, got: %q", string(data))
	}
}

func TestSignFlowErrorMessage_SignError_NoDoublePrefix(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	sfe := &signFlowError{Phase: phaseSign, Err: fmt.Errorf("some error")}
	signFlowErrorMessage(sfe, logger)
	data, err := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if err != nil {
		t.Fatalf("debug log not created: %v", err)
	}
	content := string(data)
	// Should NOT have "sign flow:" prefix for typed sign errors.
	if strings.Contains(content, "sign flow:") {
		t.Errorf("should not have 'sign flow:' prefix for sign errors, got: %q", content)
	}
}

func TestSignFlowErrorMessage_Timeout(t *testing.T) {
	// The timeout sentinel must yield a timeout message, NOT a hardware message
	// (the literal "PIN entry timed out" matches the \bpin\b classifier).
	got := signFlowErrorMessage(errPINEntryTimedOut, nil)
	if !strings.Contains(got, "timed out") {
		t.Errorf("expected timeout message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_MlockFailure(t *testing.T) {
	// The %w-wrapped mlock sentinel must yield the restart message, not a
	// misclassified hardware PIN error.
	err := fmt.Errorf("%w: mlock failed", errPINCacheUnavailable)
	got := signFlowErrorMessage(err, nil)
	if !strings.Contains(got, "secure the PIN") {
		t.Errorf("expected mlock/restart message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_IssuanceLogUnreadable(t *testing.T) {
	// The wrapped parse error must not be classified as a hardware fault.
	err := fmt.Errorf("%w: %w", errIssuanceLogUnreadable, fmt.Errorf("parsing log file: unexpected end of JSON input"))
	got := signFlowErrorMessage(err, nil)
	want := "Could not read the issuance log, so duplicates can't be checked. Signing is blocked until it is readable."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSignFlowErrorMessage_WrongPINWithRetries(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	err := &signFlowError{Phase: phaseSign, Err: fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 2})}
	got := signFlowErrorMessage(err, logger)
	if !strings.Contains(got, "2 attempt") {
		t.Errorf("expected remaining-attempts count in message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_WrongPINBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	// Retries == 0 must NOT claim "blocked" outright — it means blocked OR count
	// unavailable.
	err := &signFlowError{Phase: phaseSign, Err: fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 0})}
	got := signFlowErrorMessage(err, logger)
	if !strings.Contains(got, "locked") || strings.Contains(got, "attempt(s) left") {
		t.Errorf("expected ambiguous locked message without a positive count, got: %q", got)
	}
}

func TestSignFlowErrorMessage_TransientWinsOverPINRetries(t *testing.T) {
	// A transient reset never carries piv.AuthErr, so PINRetries can't fire; the
	// reset must map to MsgYubiKeyReset even though resetErr()'s text contains
	// "verify pin".
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(resetErr(), logger)
	if got != core.MsgYubiKeyReset {
		t.Errorf("got %q, want %q", got, core.MsgYubiKeyReset)
	}
}

func TestSignFlowErrorMessage_GenericError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(fmt.Errorf("something unexpected"), logger)
	if !strings.Contains(got, "Signing failed") {
		t.Errorf("expected signing failed message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_Transient_WrappedInSignFlowError(t *testing.T) {
	// A reset during the sign phase must yield the canonical reset message,
	// not the generic "Signing failed" message.
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	sfe := &signFlowError{Phase: phaseSign, Err: resetErr()}
	got := signFlowErrorMessage(sfe, logger)
	if got != core.MsgYubiKeyReset {
		t.Errorf("got %q, want %q", got, core.MsgYubiKeyReset)
	}
}

func TestSignFlowErrorMessage_Transient_RawAdapterOpen(t *testing.T) {
	// The raw adapter-open path (not wrapped in signFlowError) must also route
	// a reset to the canonical message.
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(resetErr(), logger)
	if got != core.MsgYubiKeyReset {
		t.Errorf("got %q, want %q", got, core.MsgYubiKeyReset)
	}
}

func TestSignFlowErrorMessage_CertificateError(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(fmt.Errorf("failed to read certificate from slot 9c: object not found"), logger)
	if !strings.Contains(got, "No signing certificate found") {
		t.Errorf("expected certificate-specific message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_CertificateWithSmartCardInError(t *testing.T) {
	// piv-go may include "smart card" in the error when slot 9c is empty.
	// This must NOT be misclassified as "YubiKey not detected".
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(fmt.Errorf("failed to read certificate from slot 9c: smart card error: data object not found"), logger)
	if !strings.Contains(got, "No signing certificate found") {
		t.Errorf("expected certificate-specific message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_NotEd25519Error(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	got := signFlowErrorMessage(fmt.Errorf("certificate does not contain an Ed25519 public key"), logger)
	if !strings.Contains(got, "No signing certificate found") {
		t.Errorf("expected certificate-specific message, got: %q", got)
	}
}

func TestSignFlowErrorMessage_NotLogged(t *testing.T) {
	tmpDir := t.TempDir()
	logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))
	pathErr := &os.PathError{Op: "open", Path: "/nonexistent/dir/log.json.tmp", Err: errors.New("no such file or directory")}
	err := &signFlowError{Phase: phaseLog, Err: fmt.Errorf("%w: %w", core.ErrNotLogged, pathErr)}

	got := signFlowErrorMessage(err, logger)
	want := "Credential signed but NOT recorded in the issuance log — check disk space/permissions."
	if got != want {
		t.Errorf("signFlowErrorMessage = %q, want %q", got, want)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "debug.log"))
	if readErr != nil {
		t.Fatalf("debug log not created: %v", readErr)
	}
	if !strings.Contains(string(data), "signed but not recorded in issuance log") {
		t.Errorf("debug log should contain the wrapped error, got: %q", string(data))
	}
}

// Every "see logs" fallback must point at the error log export, not at a raw
// debug.log file path the operator cannot easily locate.
func TestSignFlowErrorMessage_DetailsPointToExportErrorLog(t *testing.T) {
	const want = "Export the error log for details."
	cases := map[string]error{
		"export key":   &signFlowError{Phase: phaseExportKey, Err: fmt.Errorf("x")},
		"qr":           &signFlowError{Phase: phaseQR, Err: fmt.Errorf("x")},
		"sign":         &signFlowError{Phase: phaseSign, Err: fmt.Errorf("x")},
		"other phase":  &signFlowError{Phase: signFlowPhase("bogus"), Err: fmt.Errorf("x")},
		"unclassified": fmt.Errorf("something odd happened"),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			got := signFlowErrorMessage(err, nil)
			if !strings.HasSuffix(got, want) {
				t.Errorf("got %q, want suffix %q", got, want)
			}
			if strings.Contains(got, "debug.log") {
				t.Errorf("message must not reference debug.log: %q", got)
			}
		})
	}
}

func TestSentence(t *testing.T) {
	for in, want := range map[string]string{
		"":                    "",
		"file is empty":       "File is empty.",
		"Already a sentence.": "Already a sentence.",
		"what?":               "What?",
		"stop!":               "Stop!",
		"ünïcode start":       "Ünïcode start.",
	} {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q, want %q", in, got, want)
		}
	}
}
