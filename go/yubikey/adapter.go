package yubikey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"
)

// PIVProvider abstracts PIV hardware access for dependency injection.
type PIVProvider struct {
	Cards func() ([]string, error)
	Open  func(card string) (*piv.YubiKey, error)
}

// DefaultPIVProvider uses the real piv-go hardware functions.
var DefaultPIVProvider = PIVProvider{
	Cards: piv.Cards,
	Open:  piv.Open,
}

// YubiKeyAdapter talks directly to a YubiKey via PCSC for Ed25519 PIV signing.
// PIN is handled entirely in-process — never on command line, never in a file.
type YubiKeyAdapter struct {
	yk      yubiKeyHandle
	pubKey  [32]byte
	mu      sync.Mutex
	readPin func() (string, error)
}

// yubiKeyHandle abstracts the piv.YubiKey methods we use, enabling test doubles.
type yubiKeyHandle interface {
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Close() error
}

// NewYubiKeyAdapterWithProvider opens a YubiKey using the given PIV provider.
func NewYubiKeyAdapterWithProvider(provider PIVProvider, readPin func() (string, error)) (*YubiKeyAdapter, error) {
	cards, err := provider.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list smart cards: %w", err)
	}

	var cardName string
	for _, c := range cards {
		if strings.Contains(strings.ToLower(c), "yubikey") {
			cardName = c
			break
		}
	}
	if cardName == "" {
		return nil, fmt.Errorf("failed to open YubiKey: no YubiKey found among %d smart card(s)", len(cards))
	}

	yk, err := provider.Open(cardName)
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}

	return newAdapterFromHandle(yk, readPin)
}

// NewYubiKeyAdapter opens a YubiKey, reads the certificate from PIV slot 9c,
// extracts the Ed25519 public key, and returns an adapter.
// readPin is called each time a signature is needed (unless PIN is cached externally).
func NewYubiKeyAdapter(readPin func() (string, error)) (*YubiKeyAdapter, error) {
	return NewYubiKeyAdapterWithProvider(DefaultPIVProvider, readPin)
}

// newAdapterFromHandle constructs an adapter from an already-opened YubiKey handle.
func newAdapterFromHandle(yk yubiKeyHandle, readPin func() (string, error)) (*YubiKeyAdapter, error) {
	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to read certificate from slot 9c: %w", err)
	}

	edKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(edKey) != ed25519.PublicKeySize {
		yk.Close()
		return nil, fmt.Errorf("certificate does not contain an Ed25519 public key")
	}

	var pubKey [32]byte
	copy(pubKey[:], edKey)

	return &YubiKeyAdapter{
		yk:      yk,
		pubKey:  pubKey,
		readPin: readPin,
	}, nil
}

// SetReadPin replaces the PIN reader callback. Supports two-phase init where the
// adapter is created at startup (before the GUI window exists) and the PIN dialog
// is set later. Safe for concurrent use with SignBytes.
func (a *YubiKeyAdapter) SetReadPin(readPin func() (string, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readPin = readPin
}

// ExportPublicKey returns the cached Ed25519 public key from the YubiKey certificate.
func (a *YubiKeyAdapter) ExportPublicKey() ([32]byte, error) {
	return a.pubKey, nil
}

// SignBytes signs data using the YubiKey's Ed25519 private key in PIV slot 9c.
// The readPin callback is invoked to obtain the PIN for authentication.
func (a *YubiKeyAdapter) SignBytes(data []byte) ([]byte, error) {
	// Narrow lock: read readPin reference only. Do not hold during PIN
	// prompt or hardware signing — those block on user input and PCSC I/O.
	a.mu.Lock()
	rp := a.readPin
	a.mu.Unlock()
	if rp == nil {
		return nil, errors.New("PIN reader not initialized")
	}
	priv, err := a.yk.PrivateKey(
		piv.SlotSignature,
		ed25519.PublicKey(a.pubKey[:]),
		piv.KeyAuth{PINPrompt: rp},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key handle: %w", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	sig, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("expected %d-byte Ed25519 signature, got %d bytes", ed25519.SignatureSize, len(sig))
	}

	return sig, nil
}

// Close releases the connection to the YubiKey.
func (a *YubiKeyAdapter) Close() error {
	return a.yk.Close()
}

// ReadPublicKey opens a YubiKey, reads the Ed25519 public key from PIV slot 9c,
// and returns it as a base64-encoded string suitable for a registry entry's
// public_key field. No PIN required — only reads the certificate.
func ReadPublicKey() (string, error) {
	adapter, err := NewYubiKeyAdapter(func() (string, error) { return "", nil })
	if err != nil {
		return "", err
	}
	defer adapter.Close()

	pubKey, err := adapter.ExportPublicKey()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(pubKey[:]), nil
}
