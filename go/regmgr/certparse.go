package regmgr

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ExtractEd25519Key reads certificate data (.crt/.pem) and returns
// the raw 32-byte Ed25519 public key as base64.
func ExtractEd25519Key(certData []byte) (string, error) {
	var derBytes []byte

	// Try PEM decode first.
	block, _ := pem.Decode(certData)
	if block != nil {
		derBytes = block.Bytes
	} else {
		// No PEM block found — try raw DER.
		derBytes = certData
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", fmt.Errorf("not a valid certificate: %w", err)
	}

	edKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	return base64.StdEncoding.EncodeToString(edKey), nil
}
