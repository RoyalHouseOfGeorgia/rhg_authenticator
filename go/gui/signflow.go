package gui

import (
	"io"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
)

// SignFlowPhase identifies a step in the signing flow for error classification.
type SignFlowPhase string

const (
	PhaseExportKey SignFlowPhase = "export_key"
	PhaseSign      SignFlowPhase = "sign"
	PhaseQR        SignFlowPhase = "qr"
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

// executeSignFlow runs the signing workflow: open adapter, export key,
// sign, generate QR, compute hash8.
func executeSignFlow(
	req core.SignRequest,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	readPin func() (string, error),
	logger *debugLogger,
) (SignFlowResult, error) {
	// 1. Open adapter.
	adapter, closer, err := openAdapter(readPin)
	if err != nil {
		logger.log("connect: " + core.SanitizeForLog(err.Error()))
		return SignFlowResult{}, err
	}
	defer closer.Close()

	// 2. Export public key.
	pubKey, err := adapter.ExportPublicKey()
	if err != nil {
		logger.log(sanitizeError("ExportPublicKey", err))
		return SignFlowResult{}, &SignFlowError{Phase: PhaseExportKey, Err: err}
	}

	// 3. Sign.
	resp, err := core.HandleSign(req, adapter, pubKey)
	if err != nil {
		logger.log(sanitizeError("HandleSign", err))
		return SignFlowResult{}, &SignFlowError{Phase: PhaseSign, Err: err}
	}

	// 4. Build issuance record from request + response fields.
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

	// 5. Log issuance record (non-fatal — signing already succeeded).
	if logPath != "" {
		if logErr := issuancelog.AppendRecord(logPath, record); logErr != nil {
			logger.log("log append failed: " + logErr.Error())
		}
	}

	// 6. Generate QR preview.
	pngData, err := qr.GeneratePNG(resp.URL, qrPreviewPx)
	if err != nil {
		logger.log(sanitizeError("QR", err))
		return SignFlowResult{}, &SignFlowError{Phase: PhaseQR, Err: err}
	}

	// 7. First 8 hex chars of the SHA-256 hash, used as a short identifier in filenames.
	hash8 := resp.PayloadSHA256[:8]

	return SignFlowResult{
		Response:   resp,
		PNGPreview: pngData,
		Hash8:      hash8,
	}, nil
}
