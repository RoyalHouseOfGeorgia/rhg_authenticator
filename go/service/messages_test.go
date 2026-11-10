package service

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// resetErr is the real wrapped error chain seen when a PC/SC card reset
// interrupts a signing operation. It contains BOTH "verify pin" (which the old
// classifier misread as a PIN error) AND the smart-card reset phrase, proving
// the transient path wins.
func resetErr() error {
	return errors.New("sign: signing failed: verify pin: transmitting request: the smart card has been reset, so any shared state information is invalid")
}

// --- validateSignForm tests ---

func TestValidateSignForm(t *testing.T) {
	cases := []struct {
		name                           string
		recipient, honor, detail, date string
		wantErr                        bool
		wantMsg                        string // exact error text, when set
		wantContains                   string
	}{
		{name: "all valid", recipient: "John Doe", honor: honorTitles[0], detail: "For service", date: "2026-03-14"},
		{name: "empty recipient", recipient: "", honor: honorTitles[0], detail: "Detail", date: "2026-03-14", wantErr: true, wantMsg: "Recipient is required."},
		{name: "whitespace-only recipient", recipient: "   ", honor: honorTitles[0], detail: "Detail", date: "2026-03-14", wantErr: true},
		{name: "no honor selected", recipient: "John Doe", honor: "", detail: "Detail", date: "2026-03-14", wantErr: true, wantMsg: "Honor title must be selected."},
		{name: "empty detail", recipient: "John Doe", honor: honorTitles[0], detail: "", date: "2026-03-14", wantErr: true, wantMsg: "Detail is required."},
		{name: "whitespace-only detail", recipient: "John Doe", honor: honorTitles[0], detail: "  \t ", date: "2026-03-14", wantErr: true},
		{name: "invalid date bad format", recipient: "John Doe", honor: honorTitles[0], detail: "Detail", date: "not-a-date", wantErr: true, wantContains: "date"},
		{name: "invalid date Feb 30", recipient: "John Doe", honor: honorTitles[0], detail: "Detail", date: "2026-02-30", wantErr: true},
		{name: "valid leap year", recipient: "John Doe", honor: honorTitles[0], detail: "Detail", date: "2024-02-29"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSignForm(tc.recipient, tc.honor, tc.detail, tc.date)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tc.wantMsg != "" && err.Error() != tc.wantMsg {
				t.Errorf("error = %q, want %q", err, tc.wantMsg)
			}
			if tc.wantContains != "" && !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("error = %q, want containing %q", err, tc.wantContains)
			}
		})
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

// --- sanitizeError tests ---

func TestSanitizeError(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		err    error
		want   string
	}{
		{"PCSC", "test", fmt.Errorf("pcsc daemon not running"), "test: smart card service error"},
		{"PIN", "test", fmt.Errorf("wrong PIN entered"), "test: PIN error"},
		{"YubiKey", "test", fmt.Errorf("no YubiKey detected"), "test: hardware device error"},
		{"generic", "test", fmt.Errorf("unexpected failure"), "test: unexpected error"},
		{"nil", "test", nil, "test: unknown error"},
		{"card reset is transient, not a PIN error, despite verify pin in the chain", "HandleSign", resetErr(), "HandleSign: card reset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeError(tc.prefix, tc.err); got != tc.want {
				t.Errorf("sanitizeError = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- friendlyYubiKeyError tests ---

func TestFriendlyYubiKeyError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantPart   string
		wantSuffix string
	}{
		{name: "YubiKey error", err: fmt.Errorf("no YubiKey detected"), wantPart: "not detected"},
		{name: "PCSC error", err: fmt.Errorf("pcsc daemon not running"), wantPart: "Smart card service"},
		{name: "generic error", err: fmt.Errorf("unexpected failure"), wantPart: "Failed to connect", wantSuffix: "Export the error log for details."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := friendlyYubiKeyError(tc.err)
			if !strings.Contains(got, tc.wantPart) {
				t.Errorf("got %q, want containing %q", got, tc.wantPart)
			}
			if !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("got %q, want suffix %q", got, tc.wantSuffix)
			}
		})
	}
}

// --- signFlowErrorMessage tests ---

func TestSignFlowErrorMessage(t *testing.T) {
	pathErr := &os.PathError{Op: "open", Path: "/nonexistent/dir/log.json.tmp", Err: errors.New("no such file or directory")}

	cases := []struct {
		name        string
		err         error
		want        string // exact message, when set
		contains    []string
		notContains []string
	}{
		{
			name:     "export public key",
			err:      &signFlowError{Phase: phaseExportKey, Err: fmt.Errorf("hardware failure")},
			contains: []string{"Failed to read YubiKey"},
		},
		{
			name:     "QR generation",
			err:      &signFlowError{Phase: phaseQR, Err: fmt.Errorf("encode failed")},
			contains: []string{"QR generation failed"},
		},
		{
			name:     "YubiKey adapter",
			err:      fmt.Errorf("pcsc daemon not running"),
			contains: []string{"Smart card service"},
		},
		{
			name:     "sign error",
			err:      &signFlowError{Phase: phaseSign, Err: fmt.Errorf("hardware fault")},
			contains: []string{"Signing failed"},
		},
		{
			// The literal "PIN entry timed out" matches the \bpin\b classifier.
			// The text names no control: a bulk run (no Sign button) shows it too.
			name: "timeout sentinel yields a timeout message, not a hardware PIN message",
			err:  errPINEntryTimedOut,
			want: "PIN entry timed out. Try again.",
		},
		{
			name:     "wrapped mlock sentinel yields the restart message, not a hardware PIN error",
			err:      fmt.Errorf("%w: mlock failed", errPINCacheUnavailable),
			contains: []string{"secure the PIN"},
		},
		{
			name: "wrapped issuance log parse error is not a hardware fault",
			err:  fmt.Errorf("%w: %w", errIssuanceLogUnreadable, fmt.Errorf("parsing log file: unexpected end of JSON input")),
			want: "Could not read the issuance log, so duplicates can't be checked. Signing is blocked until it is readable.",
		},
		{
			name:     "wrong PIN with retries",
			err:      &signFlowError{Phase: phaseSign, Err: fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 2})},
			contains: []string{"2 attempt"},
		},
		{
			name:        "wrong PIN with zero retries means blocked or count unavailable, never a positive count",
			err:         &signFlowError{Phase: phaseSign, Err: fmt.Errorf("signing failed: %w", piv.AuthErr{Retries: 0})},
			contains:    []string{"locked"},
			notContains: []string{"attempt(s) left"},
		},
		{
			name: "transient reset wins over PIN retries despite verify pin in the text",
			err:  resetErr(),
			want: core.MsgYubiKeyReset,
		},
		{
			name:     "generic error",
			err:      fmt.Errorf("something unexpected"),
			contains: []string{"Signing failed"},
		},
		{
			name: "transient reset in the sign phase yields the reset message, not Signing failed",
			err:  &signFlowError{Phase: phaseSign, Err: resetErr()},
			want: core.MsgYubiKeyReset,
		},
		{
			name:     "certificate error",
			err:      fmt.Errorf("failed to read certificate from slot 9c: object not found"),
			contains: []string{"No signing certificate found"},
		},
		{
			name:     "certificate error mentioning smart card is not YubiKey not detected",
			err:      fmt.Errorf("failed to read certificate from slot 9c: smart card error: data object not found"),
			contains: []string{"No signing certificate found"},
		},
		{
			name: "not logged",
			err:  &signFlowError{Phase: phaseLog, Err: fmt.Errorf("%w: %w", core.ErrNotLogged, pathErr)},
			want: "Credential signed but NOT recorded in the issuance log — check disk space/permissions.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := signFlowErrorMessage(tc.err)
			if tc.want != "" && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			for _, s := range tc.contains {
				if !strings.Contains(got, s) {
					t.Errorf("got %q, want containing %q", got, s)
				}
			}
			for _, s := range tc.notContains {
				if strings.Contains(got, s) {
					t.Errorf("got %q, want not containing %q", got, s)
				}
			}
		})
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
			got := signFlowErrorMessage(err)
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
