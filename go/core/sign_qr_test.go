package core

import (
	"errors"
	"strings"
	"testing"
)

// qrReq returns a request whose only variable part is detail.
func qrReq(detail string) SignRequest {
	return SignRequest{
		Recipient: "John Doe",
		Honor:     "Test Honor",
		Detail:    detail,
		Date:      "2026-03-13",
	}
}

// urlLenFor returns the verification URL length for req, bypassing the QR
// check by canonicalizing directly (mirrors BuildPayload's construction).
func urlLenFor(t *testing.T, req SignRequest) int {
	t.Helper()
	payload, err := Canonicalize(map[string]any{
		"version":   float64(1),
		"recipient": req.Recipient,
		"honor":     req.Honor,
		"detail":    req.Detail,
		"date":      req.Date,
	})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	return VerifyURLLength(payload)
}

func assertTooLong(t *testing.T, err error, wantOver int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected ErrTooLongForQR, got nil")
	}
	if !errors.Is(err, ErrTooLongForQR) {
		t.Fatalf("errors.Is(err, ErrTooLongForQR) = false; err = %v", err)
	}
	if errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("too-long error must not match ErrInvalidCredential: %v", err)
	}
	var tl *TooLongForQRError
	if !errors.As(err, &tl) {
		t.Fatalf("errors.As(*TooLongForQRError) = false; err = %v", err)
	}
	if wantOver >= 0 && tl.OverBytes != wantOver {
		t.Fatalf("OverBytes = %d, want %d", tl.OverBytes, wantOver)
	}
	if tl.OverBytes < 1 {
		t.Fatalf("OverBytes = %d, want >= 1", tl.OverBytes)
	}
}

// TestBuildPayload_QRBoundaryASCII pins the strict `>` boundary: a URL of
// exactly MaxVerifyURLLength must build, one character over must fail.
func TestBuildPayload_QRBoundaryASCII(t *testing.T) {
	// Find the longest ASCII detail whose URL fits, then confirm the exact length.
	detail := ""
	for urlLenFor(t, qrReq(detail+"x")) <= MaxVerifyURLLength {
		detail += "x"
	}
	// Unpadded base64 never has length 4k+1, so exact landing depends on the
	// baseline; fail loudly if a fixture change makes 625 unreachable.
	n := urlLenFor(t, qrReq(detail))
	if n != MaxVerifyURLLength {
		t.Fatalf("ASCII padding landed on %d, not exactly %d; test needs another pad strategy", n, MaxVerifyURLLength)
	}
	if _, err := BuildPayload(qrReq(detail)); err != nil {
		t.Fatalf("URL of exactly %d should build, got %v", MaxVerifyURLLength, err)
	}

	over := detail + "x"
	if got := urlLenFor(t, qrReq(over)); got != MaxVerifyURLLength+1 {
		t.Fatalf("one more byte gave URL length %d, want %d", got, MaxVerifyURLLength+1)
	}
	_, err := BuildPayload(qrReq(over))
	assertTooLong(t, err, 1)
}

// TestBuildPayload_QRBoundaryGeorgian pads with a 3-byte Georgian letter, which
// adds exactly 4 base64url characters per letter, so the boundary is crossed in
// steps of 4: the last fitting count builds, the next one fails.
func TestBuildPayload_QRBoundaryGeorgian(t *testing.T) {
	const ka = "ა" // Georgian letter "an" (3 bytes UTF-8)
	count := 0
	for urlLenFor(t, qrReq(strings.Repeat(ka, count+1))) <= MaxVerifyURLLength {
		count++
	}
	if count == 0 {
		t.Fatal("baseline already too long for any Georgian padding")
	}

	fit := strings.Repeat(ka, count)
	if n := urlLenFor(t, qrReq(fit)); n > MaxVerifyURLLength {
		t.Fatalf("last fitting count gave URL length %d", n)
	}
	if _, err := BuildPayload(qrReq(fit)); err != nil {
		t.Fatalf("%d Georgian letters should build, got %v", count, err)
	}

	over := strings.Repeat(ka, count+1)
	overLen := urlLenFor(t, qrReq(over))
	if overLen <= MaxVerifyURLLength {
		t.Fatalf("first over count gave URL length %d", overLen)
	}
	_, err := BuildPayload(qrReq(over))
	assertTooLong(t, err, ((overLen-MaxVerifyURLLength)*3+3)/4)
}

// TestBuildPayload_TooLongOverBytesScales checks OverBytes reflects how far
// over the limit a long detail is (roughly 1:1 in ASCII bytes).
func TestBuildPayload_TooLongOverBytesScales(t *testing.T) {
	detail := ""
	for urlLenFor(t, qrReq(detail+"x")) <= MaxVerifyURLLength {
		detail += "x"
	}
	_, err := BuildPayload(qrReq(detail + strings.Repeat("x", 30)))
	assertTooLong(t, err, 30)
}

func TestVerifyURLLength_MatchesHandleSign(t *testing.T) {
	adapter := &mockAdapter{secretKey: testSecretKey()}
	for _, detail := range []string{"x", "For service", strings.Repeat("ა", 50)} {
		req := qrReq(detail)
		resp, err := HandleSign(req, adapter, testPubKey())
		if err != nil {
			t.Fatalf("HandleSign(%q): %v", detail, err)
		}
		payload, err := BuildPayload(req)
		if err != nil {
			t.Fatalf("BuildPayload: %v", err)
		}
		if got := VerifyURLLength(payload); got != len(resp.URL) {
			t.Errorf("VerifyURLLength = %d, len(resp.URL) = %d", got, len(resp.URL))
		}
	}
}

func TestHandleSign_TooLongForQRNotSigned(t *testing.T) {
	adapter := &countingAdapter{mockAdapter: mockAdapter{secretKey: testSecretKey()}}
	_, err := HandleSign(qrReq(strings.Repeat("x", 600)), adapter, testPubKey())
	assertTooLong(t, err, -1)
	if adapter.calls != 0 {
		t.Errorf("SignBytes called %d times for an over-long credential", adapter.calls)
	}
}

// countingAdapter records SignBytes calls.
type countingAdapter struct {
	mockAdapter
	calls int
}

func (c *countingAdapter) SignBytes(data []byte) ([]byte, error) {
	c.calls++
	return c.mockAdapter.SignBytes(data)
}

func TestBuildPayload_ErrInvalidCredential(t *testing.T) {
	tests := []struct {
		name string
		req  SignRequest
	}{
		{"bad date", SignRequest{"A", "B", "C", "2026-02-30"}},
		{"control char in detail", SignRequest{"A", "B", "a\x07b", "2026-03-13"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildPayload(tt.req)
			if !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("errors.Is(err, ErrInvalidCredential) = false; err = %v", err)
			}
			if errors.Is(err, ErrTooLongForQR) {
				t.Fatalf("invalid credential must not match ErrTooLongForQR: %v", err)
			}
			if !strings.HasPrefix(err.Error(), "invalid credential data: ") {
				t.Errorf("message = %q, want prefix %q", err.Error(), "invalid credential data: ")
			}
		})
	}
}

func TestTooLongForQRError_Error(t *testing.T) {
	tests := []struct {
		over int
		want string
	}{
		{10, "too long to fit in a QR code by about 10 letters (about 4 in Georgian script) — shorten the detail or recipient"},
		{9, "too long to fit in a QR code by about 9 letters (about 3 in Georgian script) — shorten the detail or recipient"},
		{1, "too long to fit in a QR code by about 1 letter (about 1 in Georgian script) — shorten the detail or recipient"},
		{2, "too long to fit in a QR code by about 2 letters (about 1 in Georgian script) — shorten the detail or recipient"},
	}
	for _, tt := range tests {
		if got := (&TooLongForQRError{OverBytes: tt.over}).Error(); got != tt.want {
			t.Errorf("Error(%d) = %q, want %q", tt.over, got, tt.want)
		}
	}
}

func TestTooLongForQRError_Overage(t *testing.T) {
	tests := []struct {
		over int
		want string
	}{
		{1, "about 1 letter (about 1 in Georgian script)"},
		{3, "about 3 letters (about 1 in Georgian script)"},
		{4, "about 4 letters (about 2 in Georgian script)"},
	}
	for _, tt := range tests {
		if got := (&TooLongForQRError{OverBytes: tt.over}).Overage(); got != tt.want {
			t.Errorf("Overage(%d) = %q, want %q", tt.over, got, tt.want)
		}
	}
}

func TestTooLongForQRError_Is(t *testing.T) {
	e := &TooLongForQRError{OverBytes: 1}
	if !e.Is(ErrTooLongForQR) {
		t.Error("Is(ErrTooLongForQR) = false")
	}
	if e.Is(ErrInvalidCredential) || e.Is(errors.New("too long to fit in a QR code")) {
		t.Error("Is matched an unrelated error")
	}
}
