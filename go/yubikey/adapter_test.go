package yubikey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// --- Test doubles ---

// fakeYubiKey implements yubiKeyHandle for unit testing without hardware.
type fakeYubiKey struct {
	cert       *x509.Certificate
	certErr    error
	privKey    crypto.PrivateKey
	privKeyErr error
	closed     bool
	closeErr   error
}

func (f *fakeYubiKey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	return f.cert, f.certErr
}

func (f *fakeYubiKey) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	// If PINPrompt is set, call it to simulate real behavior.
	if auth.PINPrompt != nil {
		pin, err := auth.PINPrompt()
		if err != nil {
			return nil, err
		}
		if pin == "" {
			return nil, errors.New("pin required but wasn't provided")
		}
	}
	return f.privKey, f.privKeyErr
}

func (f *fakeYubiKey) Close() error {
	f.closed = true
	return f.closeErr
}

// fakeSigner wraps an ed25519.PrivateKey to implement crypto.Signer.
type fakeSigner struct {
	key ed25519.PrivateKey
}

func (s *fakeSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *fakeSigner) Sign(_ io.Reader, data []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(s.key, data), nil
}

// badLengthSigner returns a signature with wrong length.
type badLengthSigner struct {
	key ed25519.PrivateKey
}

func (s *badLengthSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *badLengthSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return make([]byte, 48), nil
}

// errorSigner returns an error from Sign.
type errorSigner struct {
	key ed25519.PrivateKey
}

func (s *errorSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *errorSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("hardware error")
}

// nonSigner is a crypto.PrivateKey that does not implement crypto.Signer.
type nonSigner struct{}

// --- Helpers ---

func testEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, 32)
	seed[0] = 0x42
	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	return pk, sk
}

func testCert(pub ed25519.PublicKey) *x509.Certificate {
	return &x509.Certificate{PublicKey: pub}
}

func staticPin(pin string) func() (string, error) {
	return func() (string, error) { return pin, nil }
}

// --- Tests ---

func TestNewYubiKeyAdapter_NoHardware(t *testing.T) {
	// In CI or any environment without a YubiKey, NewYubiKeyAdapter should
	// return an error rather than panic.
	_, err := NewYubiKeyAdapter(staticPin("123456"))
	if err == nil {
		t.Skip("YubiKey hardware detected; skipping no-hardware test")
	}
	// Should mention "YubiKey" or "smart card" in the error.
	if err.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestNewAdapterFromHandle_Success(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{cert: testCert(pub)}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	got, err := adapter.ExportPublicKey()
	if err != nil {
		t.Fatalf("ExportPublicKey error: %v", err)
	}

	var want [32]byte
	copy(want[:], pub)
	if got != want {
		t.Errorf("public key mismatch: got %x, want %x", got, want)
	}
}

func TestNewAdapterFromHandle_CertError(t *testing.T) {
	yk := &fakeYubiKey{certErr: errors.New("no cert")}

	_, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !yk.closed {
		t.Error("expected YubiKey to be closed on error")
	}
	want := "failed to read certificate from slot 9c"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Errorf("error %q does not contain %q", got, want)
	}
}

func TestNewAdapterFromHandle_NotEd25519(t *testing.T) {
	// Certificate with an RSA key instead of Ed25519.
	yk := &fakeYubiKey{cert: &x509.Certificate{PublicKey: "not-a-key"}}

	_, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err == nil {
		t.Fatal("expected error for non-Ed25519 key")
	}
	if !yk.closed {
		t.Error("expected YubiKey to be closed on error")
	}
	want := "certificate does not contain an Ed25519 public key"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Errorf("error %q does not contain %q", got, want)
	}
}

func TestSignBytes_Success(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &fakeSigner{key: sk},
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	data := []byte("test message")
	sig, err := adapter.SignBytes(data)
	if err != nil {
		t.Fatalf("SignBytes error: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pub, data, sig) {
		t.Error("signature verification failed")
	}
}

func TestSignBytes_PinCancelled(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &fakeSigner{key: sk},
	}

	cancelPin := func() (string, error) { return "", nil }

	adapter, err := newAdapterFromHandle(yk, cancelPin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error when PIN is empty")
	}
}

func TestSignBytes_PinError(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &fakeSigner{key: sk},
	}

	errPin := func() (string, error) { return "", errors.New("user cancelled") }

	adapter, err := newAdapterFromHandle(yk, errPin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error when PIN callback errors")
	}
}

func TestSignBytes_PrivateKeyError(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{
		cert:       testCert(pub),
		privKeyErr: errors.New("slot locked"),
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to get private key handle") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignBytes_NotCryptoSigner(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: nonSigner{},
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "does not implement crypto.Signer") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignBytes_WrongSignatureLength(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &badLengthSigner{key: sk},
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}
	if !strings.Contains(err.Error(), "expected 64-byte Ed25519 signature") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignBytes_SignError(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &errorSigner{key: sk},
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "signing failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClose(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{cert: testCert(pub)}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if !yk.closed {
		t.Error("expected YubiKey to be closed")
	}
}

func TestClose_Error(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{cert: testCert(pub), closeErr: errors.New("close failed")}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := adapter.Close(); err == nil {
		t.Fatal("expected error from Close")
	}
}

func TestSigningAdapterCompliance(t *testing.T) {
	// Compile-time check that YubiKeyAdapter satisfies the method set
	// expected by core.SigningAdapter (ExportPublicKey + SignBytes).
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &fakeSigner{key: sk},
	}

	adapter, err := newAdapterFromHandle(yk, staticPin("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	// Verify the two methods that core.SigningAdapter requires.
	if _, err := adapter.ExportPublicKey(); err != nil {
		t.Errorf("ExportPublicKey: %v", err)
	}
	if _, err := adapter.SignBytes([]byte("test")); err != nil {
		t.Errorf("SignBytes: %v", err)
	}
}

func TestNewYubiKeyAdapter_CardsError(t *testing.T) {
	origCards := pivCardsFunc
	defer func() { pivCardsFunc = origCards }()

	pivCardsFunc = func() ([]string, error) {
		return nil, errors.New("pcsc daemon not running")
	}

	_, err := NewYubiKeyAdapter(staticPin("123456"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to list smart cards") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewYubiKeyAdapter_NoYubiKeyFound(t *testing.T) {
	origCards := pivCardsFunc
	defer func() { pivCardsFunc = origCards }()

	pivCardsFunc = func() ([]string, error) {
		return []string{"Some Other Card"}, nil
	}

	_, err := NewYubiKeyAdapter(staticPin("123456"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no YubiKey found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewYubiKeyAdapter_OpenError(t *testing.T) {
	origCards := pivCardsFunc
	origOpen := pivOpenFunc
	defer func() {
		pivCardsFunc = origCards
		pivOpenFunc = origOpen
	}()

	pivCardsFunc = func() ([]string, error) {
		return []string{"Yubico YubiKey 5 NFC"}, nil
	}
	pivOpenFunc = func(card string) (*piv.YubiKey, error) {
		return nil, errors.New("device busy")
	}

	_, err := NewYubiKeyAdapter(staticPin("123456"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to open YubiKey") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewYubiKeyAdapter_EmptyCardList(t *testing.T) {
	origCards := pivCardsFunc
	defer func() { pivCardsFunc = origCards }()

	pivCardsFunc = func() ([]string, error) {
		return []string{}, nil
	}

	_, err := NewYubiKeyAdapter(staticPin("123456"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no YubiKey found among 0") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignBytes_NilReadPin(t *testing.T) {
	pub, _ := testEd25519Key()
	yk := &fakeYubiKey{cert: testCert(pub)}

	adapter, err := newAdapterFromHandle(yk, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error when readPin is nil")
	}
	if err.Error() != "PIN reader not initialized" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSignBytes_SetReadPinAfterNil(t *testing.T) {
	pub, sk := testEd25519Key()
	yk := &fakeYubiKey{
		cert:    testCert(pub),
		privKey: &fakeSigner{key: sk},
	}

	// Create adapter with nil readPin.
	adapter, err := newAdapterFromHandle(yk, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer adapter.Close()

	// Should fail before SetReadPin.
	_, err = adapter.SignBytes([]byte("data"))
	if err == nil {
		t.Fatal("expected error when readPin is nil")
	}

	// Set a valid readPin and retry.
	adapter.SetReadPin(staticPin("123456"))
	sig, err := adapter.SignBytes([]byte("data"))
	if err != nil {
		t.Fatalf("SignBytes failed after SetReadPin: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}
}

