package core

import (
	"encoding/base64"
	"errors"
)

// maxStdBase64Input is the maximum allowed length for standard Base64 input
// to DecodeStandard. Matches the TypeScript MAX_B64_INPUT = 256.
const maxStdBase64Input = 256

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

// DecodeStandard decodes a standard padded Base64 string to bytes.
// It enforces a maximum input length of 256 characters.
func DecodeStandard(s string) ([]byte, error) {
	if len(s) > maxStdBase64Input {
		return nil, errors.New("base64: input exceeds maximum length")
	}
	return base64.StdEncoding.DecodeString(s)
}
