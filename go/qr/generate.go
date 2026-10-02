package qr

import (
	"bytes"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// QRMaxURLLength is the maximum URL length accepted for QR code generation,
// keeping the module count reasonable for print.
const QRMaxURLLength = 625

// newQR validates the URL length and creates a QR code at skip2's qrcode.High,
// which is error correction level Q (25%).
func newQR(url string) (*qrcode.QRCode, error) {
	if len(url) > QRMaxURLLength {
		return nil, fmt.Errorf("URL exceeds maximum length (%d > %d)", len(url), QRMaxURLLength)
	}
	return qrcode.New(url, qrcode.High)
}

// GenerateSVG generates a QR code as SVG bytes (vector format, scales to any print size).
// Error correction level Q (25%). Version auto-selected.
// SVG is manually rendered: header + rect per dark module. Bitmap() already
// includes skip2's 4-module quiet zone, and 4 more modules are added on each
// side, so viewBox = bitmap size + 8.
func GenerateSVG(url string) ([]byte, error) {
	qr, err := newQR(url)
	if err != nil {
		return nil, fmt.Errorf("creating QR code: %w", err)
	}

	bitmap := qr.Bitmap()
	n := len(bitmap)
	total := n + 8 // 4 extra modules on each side, on top of skip2's quiet zone

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buf.WriteByte('\n')
	fmt.Fprintf(&buf, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d">`, total, total)
	buf.WriteByte('\n')
	fmt.Fprintf(&buf, `<rect width="%d" height="%d" fill="white"/>`, total, total)
	buf.WriteByte('\n')

	for y, row := range bitmap {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="1" height="1" fill="black"/>`, x+4, y+4)
				buf.WriteByte('\n')
			}
		}
	}

	buf.WriteString(`</svg>`)
	buf.WriteByte('\n')

	return buf.Bytes(), nil
}

// GeneratePNG generates a QR code as PNG bytes (512px preview, 2048px for Save PNG).
// Error correction level Q (25%). Version auto-selected.
func GeneratePNG(url string, width int) ([]byte, error) {
	qr, err := newQR(url)
	if err != nil {
		return nil, fmt.Errorf("creating QR code: %w", err)
	}

	png, err := qr.PNG(width)
	if err != nil {
		return nil, fmt.Errorf("encoding PNG: %w", err)
	}

	return png, nil
}
