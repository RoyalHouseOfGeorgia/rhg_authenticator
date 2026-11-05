//go:build rhgfake

package service

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
)

// The rhgfake test build signs with a software card instead of a YubiKey, so
// signing flows run end to end with no hardware. Its key is derived from a
// fixed phrase: it is public test data, never a real signing key.

// FakeCardPIN is the only PIN the fake card accepts.
const FakeCardPIN = "123456"

// fakeCardRetries is the retry count a wrong PIN reports. The fake card never
// blocks, so it stays constant.
const fakeCardRetries = 2

// fakeCardKey is the fake card's signing key.
var fakeCardKey = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("rhgfake test card"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

func init() { openYubiKey = openFakeCard }

// FakeCardPublicKey returns the fake card's Ed25519 public key.
func FakeCardPublicKey() [32]byte {
	var pub [32]byte
	copy(pub[:], fakeCardKey.Public().(ed25519.PublicKey))
	return pub
}

// SetPINTimeoutForTest sets how long a's PIN prompt waits for an answer.
// Call it before a is shared with other goroutines. It is a function, not an
// App method, so the App method set is the same in every build.
func SetPINTimeoutForTest(a *App, d time.Duration) { a.pinTimeout = d }

// openFakeCard is the rhgfake adapterOpener.
func openFakeCard(readPin func() (string, error)) (core.SigningAdapter, io.Closer, error) {
	c := &fakeCard{readPin: readPin}
	return c, c, nil
}

// fakeCard behaves like yubikey.YubiKeyAdapter on a freshly opened card: the
// public key needs no PIN, and each SignBytes asks readPin for the PIN and
// verifies it before signing. Its errors wrap like piv-go's: a readPin error
// by value ("pin prompt: %v"), a wrong PIN as piv.AuthErr (so
// yubikey.IsPINAuthError matches). It never logs or keeps the PIN.
type fakeCard struct {
	readPin func() (string, error)
}

func (c *fakeCard) ExportPublicKey() ([32]byte, error) { return FakeCardPublicKey(), nil }

func (c *fakeCard) SignBytes(data []byte) ([]byte, error) {
	pin, err := c.readPin()
	if err != nil {
		return nil, fmt.Errorf("signing failed: pin prompt: %v", err)
	}
	if pin != FakeCardPIN {
		return nil, fmt.Errorf("signing failed: verify pin: %w", piv.AuthErr{Retries: fakeCardRetries})
	}
	return ed25519.Sign(fakeCardKey, data), nil
}

func (c *fakeCard) Close() error { return nil }
