//go:build ignore

// gen_vectors.go regenerates the cross-language test vectors for the RHG Authenticator.
// Run from the repo root: go run ./go/testdata/gen_vectors.go
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

type vector struct {
	Name       string         `json:"name"`
	Credential map[string]any `json:"credential"`
	CanonHex   string         `json:"canonical_hex"`
	PayloadB64 string         `json:"payload_b64url"`
	SigB64     string         `json:"signature_b64url"`
	URL        string         `json:"url"`
	PubKeyHex  string         `json:"public_key_hex"`
}

func main() {
	// Deterministic test key: seed is 0x01 followed by 31 zero bytes.
	seed := make([]byte, 32)
	seed[0] = 0x01
	sk := ed25519.NewKeyFromSeed(seed)
	pub := sk.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)

	credentials := []struct {
		name string
		cred map[string]any
	}{
		{
			name: "ascii_only",
			cred: map[string]any{
				"version":   float64(1),
				"recipient": "John Doe",
				"honor":     "Test Honor",
				"detail":    "For service",
				"date":      "2026-03-13",
			},
		},
		{
			name: "georgian_text",
			cred: map[string]any{
				"version":   float64(1),
				"recipient": "ქართველი",
				"honor":     "Test Honor",
				"detail":    "საქართველოს სამეფო",
				"date":      "2026-03-13",
			},
		},
		{
			name: "nfc_edge_case",
			cred: map[string]any{
				"version":   float64(1),
				"recipient": "Caf\u00e9",   // NFC form
				"honor":     "Test Honor",
				"detail":    "r\u00e9sum\u00e9", // NFC form
				"date":      "2026-03-13",
			},
		},
	}

	vectors := make([]vector, 0, len(credentials))
	for _, c := range credentials {
		canonical, err := core.Canonicalize(c.cred)
		if err != nil {
			fmt.Fprintf(os.Stderr, "canonicalize %s: %v\n", c.name, err)
			os.Exit(1)
		}

		sig := ed25519.Sign(sk, canonical)
		payloadB64 := core.Encode(canonical)
		sigB64 := core.Encode(sig)
		url := core.VerifyBaseURL + "?p=" + payloadB64 + "&s=" + sigB64

		// Build the credential for the JSON output with int version (not float).
		credOut := map[string]any{
			"version":   1,
			"recipient": c.cred["recipient"],
			"honor":     c.cred["honor"],
			"detail":    c.cred["detail"],
			"date":      c.cred["date"],
		}

		vectors = append(vectors, vector{
			Name:       c.name,
			Credential: credOut,
			CanonHex:   hex.EncodeToString(canonical),
			PayloadB64: payloadB64,
			SigB64:     sigB64,
			URL:        url,
			PubKeyHex:  pubHex,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(vectors); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(1)
	}
}
