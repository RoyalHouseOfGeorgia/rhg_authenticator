package core

import (
	"encoding/base64"
	"errors"
)

// Encode encodes data to an unpadded Base64URL string.
func Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Decode decodes a Base64URL string (padded or unpadded) to bytes.
// It rejects inputs where len%4 == 1 after stripping padding, which
// is invalid Base64 that Go's decoder silently mishandles.
func Decode(s string) ([]byte, error) {
	// Strip any trailing padding the caller may have included.
	clean := s
	for len(clean) > 0 && clean[len(clean)-1] == '=' {
		clean = clean[:len(clean)-1]
	}

	if len(clean)%4 == 1 {
		return nil, errors.New("base64url: invalid input length")
	}

	return base64.RawURLEncoding.DecodeString(clean)
}
