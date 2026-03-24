package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandomHex returns a string of exactly n random hexadecimal characters.
// Returns an error if n is negative or if the random source fails.
func RandomHex(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("RandomHex: n must be non-negative, got %d", n)
	}
	if n == 0 {
		return "", nil
	}
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:n], nil
}
