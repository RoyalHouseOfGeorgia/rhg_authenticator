package gui

import (
	"fmt"
	"io"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/qr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
)

// SignFlowResult holds the output of a successful signing operation.
type SignFlowResult struct {
	Response   core.SignResponse
	PNGPreview []byte
	Hash8      string
}

// executeSignFlow runs the signing workflow: open adapter, export key,
// find authority, sign, generate QR, compute hash8.
func executeSignFlow(
	req core.SignRequest,
	reg core.Registry,
	logPath string,
	openAdapter func(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error),
	readPin func() (string, error),
	logger *debugLogger,
) (SignFlowResult, error) {
	// 1. Open adapter.
	adapter, closer, err := openAdapter(readPin)
	if err != nil {
		return SignFlowResult{}, err
	}
	defer closer.Close()

	// 2. Export public key.
	pubKey, err := adapter.ExportPublicKey()
	if err != nil {
		logger.log(sanitizeError("ExportPublicKey", err))
		return SignFlowResult{}, fmt.Errorf("export public key: %w", err)
	}

	// 3. Find matching authority.
	authority, err := registry.FindMatchingAuthorityAt(reg, pubKey, time.Now().Format("2006-01-02"))
	if err != nil {
		return SignFlowResult{}, err
	}

	// 4. Sign.
	resp, err := core.HandleSign(req, adapter, pubKey, authority, logPath)
	if err != nil {
		logger.log(sanitizeError("HandleSign", err))
		return SignFlowResult{}, err
	}

	// 5. Generate QR preview.
	pngData, err := qr.GeneratePNG(resp.URL, qrPreviewPx)
	if err != nil {
		logger.log(sanitizeError("QR", err))
		return SignFlowResult{}, fmt.Errorf("QR generation: %w", err)
	}

	// 6. Compute hash8 from PayloadSHA256 (set by HandleSign).
	hash8 := resp.PayloadSHA256[:8]

	return SignFlowResult{
		Response:   resp,
		PNGPreview: pngData,
		Hash8:      hash8,
	}, nil
}
