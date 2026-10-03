package gui

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
)

// inputReq returns a sign request with the given detail; all other fields are
// valid.
func inputReq(detail string) core.SignRequest {
	return core.SignRequest{
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
		Detail:    detail,
		Date:      "2026-03-14",
	}
}

// TestExecuteSignFlow_InputErrorsRefusedBeforePIN verifies that a request too
// long for a QR code, or failing validation, is refused before the PIN prompt
// and before any card access — with or without an issuance log path.
func TestExecuteSignFlow_InputErrorsRefusedBeforePIN(t *testing.T) {
	cases := []struct {
		name    string
		req     core.SignRequest
		wantErr error
	}{
		{"too long for QR", inputReq(strings.Repeat("x", 600)), core.ErrTooLongForQR},
		{"detail over field limit", inputReq(strings.Repeat("x", 2001)), core.ErrInvalidCredential},
		{"invalid date", core.SignRequest{Recipient: "A", Honor: "B", Detail: "C", Date: "2026-02-30"}, core.ErrInvalidCredential},
	}
	for _, tc := range cases {
		for _, withLog := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/log=%v", tc.name, withLog), func(t *testing.T) {
				tmpDir := t.TempDir()
				logPath := ""
				if withLog {
					logPath = filepath.Join(tmpDir, "issuance.log")
				}
				logger := debuglog.New(filepath.Join(tmpDir, "debug.log"))

				pinCalls, openCalls := 0, 0
				readPin := func() (string, error) { pinCalls++; return "123456", nil }
				openAdapter := func(func() (string, error)) (core.SigningAdapter, io.Closer, error) {
					openCalls++
					return nil, nil, errors.New("must not be called")
				}

				_, err := executeSignFlow(tc.req, logPath, openAdapter, readPin, nil, logger)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is %v", err, tc.wantErr)
				}
				if pinCalls != 0 {
					t.Errorf("readPin called %d times, want 0", pinCalls)
				}
				if openCalls != 0 {
					t.Errorf("openAdapter called %d times, want 0", openCalls)
				}
			})
		}
	}
}

func TestSignFlowErrorMessage_TooLongForQR(t *testing.T) {
	cases := []struct {
		over int
		want string
	}{
		{10, "Too long to fit in a QR code by about 10 letters (about 4 in Georgian script) — shorten the detail or recipient."},
		{1, "Too long to fit in a QR code by about 1 letter (about 1 in Georgian script) — shorten the detail or recipient."},
	}
	for _, tc := range cases {
		err := error(&core.TooLongForQRError{OverBytes: tc.over})
		if got := signFlowErrorMessage(err, nil); got != tc.want {
			t.Errorf("bare OverBytes=%d: got %q, want %q", tc.over, got, tc.want)
		}
		wrapped := &SignFlowError{Phase: PhaseSign, Err: err}
		if got := signFlowErrorMessage(wrapped, nil); got != tc.want {
			t.Errorf("wrapped OverBytes=%d: got %q, want %q", tc.over, got, tc.want)
		}
	}
}

// TestSignFlowErrorMessage_TooLongFromBuildPayload exercises the real error
// produced by BuildPayload and checks the Sign tab shows the same text Bulk
// Sign does (the core message), capitalized with a full stop.
func TestSignFlowErrorMessage_TooLongFromBuildPayload(t *testing.T) {
	_, err := core.BuildPayload(inputReq(strings.Repeat("x", 600)))
	got := signFlowErrorMessage(err, nil)
	if !strings.HasSuffix(got, " — shorten the detail or recipient.") || strings.Contains(got, "..") {
		t.Errorf("unexpected message: %q", got)
	}
	if !strings.HasPrefix(got, "Too long to fit in a QR code by about ") {
		t.Errorf("unexpected message: %q", got)
	}
}

func TestSignFlowErrorMessage_InvalidCredential(t *testing.T) {
	_, bare := core.BuildPayload(inputReq(strings.Repeat("x", 2001)))
	if !errors.Is(bare, core.ErrInvalidCredential) {
		t.Fatalf("setup: want ErrInvalidCredential, got %v", bare)
	}
	want := "Invalid credential data: detail exceeds maximum length of 2000."
	cases := map[string]error{
		"bare":    bare,
		"wrapped": &SignFlowError{Phase: PhaseSign, Err: bare},
		"double":  fmt.Errorf("outer: %w", &SignFlowError{Phase: PhaseSign, Err: bare}),
	}
	for name, err := range cases {
		if got := signFlowErrorMessage(err, nil); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

// TestSignFlowErrorMessage_InvalidCredentialSanitized verifies control
// characters in the reason are stripped from the status text.
func TestSignFlowErrorMessage_InvalidCredentialSanitized(t *testing.T) {
	err := &core.InvalidCredentialError{Reason: errors.New("bad\x07 field\x1b")}
	if got, want := signFlowErrorMessage(err, nil), "Invalid credential data: bad field."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCapitalize(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "Abc", "Abc": "Abc", "ábc": "Ábc", "1a": "1a"} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsOperatorInputError(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"too long":        {&core.TooLongForQRError{OverBytes: 1}, true},
		"invalid":         {&core.InvalidCredentialError{Reason: errors.New("x")}, true},
		"wrapped invalid": {&SignFlowError{Phase: PhaseSign, Err: &core.InvalidCredentialError{Reason: errors.New("x")}}, true},
		"cancelled":       {ErrSigningCancelled, false},
		"generic":         {errors.New("boom"), false},
	}
	for name, tc := range cases {
		if got := isOperatorInputError(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestSignIssueBody_OmitsRawError(t *testing.T) {
	err := &SignFlowError{Phase: PhaseQR, Err: errors.New("open /home/alice/secret/issuance.log: denied")}
	msg := "QR generation failed. Use Help → Export Error Log… for details."
	body := signIssueBody(err, msg)
	if strings.Contains(body, "/home/alice/secret") {
		t.Errorf("body leaks raw error text: %q", body)
	}
	if !strings.Contains(body, msg) {
		t.Errorf("body missing user message: %q", body)
	}
	if !strings.Contains(body, "(phase: qr)") {
		t.Errorf("body missing phase: %q", body)
	}
	if strings.Contains(body, "hardware: ") {
		t.Errorf("non-hardware error should not carry a hardware tag: %q", body)
	}
}

func TestSignIssueBody_PlainErrorHasNoPhase(t *testing.T) {
	body := signIssueBody(errors.New("/home/alice/secret broke"), "Unexpected error.")
	if strings.Contains(body, "phase:") {
		t.Errorf("plain error should not carry a phase: %q", body)
	}
	if strings.Contains(body, "/home/alice/secret") {
		t.Errorf("body leaks raw error text: %q", body)
	}
	if !strings.Contains(body, "Unexpected error.") {
		t.Errorf("body missing user message: %q", body)
	}
}

func TestSignIssueBody_HardwareCategory(t *testing.T) {
	err := errors.New("reader 'Alice YubiKey 5' at /home/alice/secret: pcsc daemon not running")
	if core.ClassifyHardwareError(err) == "" {
		t.Fatal("setup: error should classify as hardware")
	}
	body := signIssueBody(err, "Smart card service is not running.")
	if !strings.Contains(body, "(hardware: "+core.HwErrSmartcard+")") {
		t.Errorf("body missing hardware category: %q", body)
	}
	if strings.Contains(body, "Alice YubiKey") || strings.Contains(body, "/home/alice/secret") {
		t.Errorf("body leaks raw error text: %q", body)
	}
}

func TestSignIssueBody_PhaseAndHardware(t *testing.T) {
	err := &SignFlowError{Phase: PhaseExportKey, Err: errors.New("pcsc daemon not running")}
	body := signIssueBody(err, "Failed to read YubiKey.")
	if !strings.Contains(body, "Failed to read YubiKey. (phase: export_key) (hardware: smartcard)") {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestOfferIssueReport(t *testing.T) {
	_, invalid := core.BuildPayload(core.SignRequest{Recipient: "A", Honor: "B", Detail: "C", Date: "2026-02-30"})
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"cancelled", ErrSigningCancelled, false},
		{"timed out", ErrPINEntryTimedOut, false},
		{"too long", &core.TooLongForQRError{OverBytes: 5}, false},
		{"too long wrapped", &SignFlowError{Phase: PhaseSign, Err: &core.TooLongForQRError{OverBytes: 5}}, false},
		{"invalid credential", invalid, false},
		{"generic", errors.New("something broke"), true},
		{"sign phase", &SignFlowError{Phase: PhaseSign, Err: errors.New("hardware fault")}, true},
	}
	for _, tc := range cases {
		if got := offerIssueReport(tc.err); got != tc.want {
			t.Errorf("%s: offerIssueReport = %v, want %v", tc.name, got, tc.want)
		}
	}
}
