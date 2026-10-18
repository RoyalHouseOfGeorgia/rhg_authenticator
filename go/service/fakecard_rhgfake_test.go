//go:build rhgfake

package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// pinReader returns a readPin that answers pin (or err) and counts calls.
func pinReader(pin string, err error) (func() (string, error), *int) {
	calls := new(int)
	return func() (string, error) { *calls++; return pin, err }, calls
}

func TestFakeCard_SignsWithItsPublicKey(t *testing.T) {
	readPin, calls := pinReader(FakeCardPIN, nil)
	adapter, closer, err := openYubiKey(readPin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pub, err := adapter.ExportPublicKey()
	if err != nil || pub != FakeCardPublicKey() {
		t.Fatalf("ExportPublicKey = %x, %v; want %x", pub, err, FakeCardPublicKey())
	}
	if *calls != 0 {
		t.Fatalf("reading the public key asked for the PIN %d times", *calls)
	}
	msg := []byte("payload")
	sig, err := adapter.SignBytes(msg)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if !ed25519.Verify(pub[:], msg, sig) {
		t.Fatal("signature does not verify with the fake card's public key")
	}
	if *calls != 1 {
		t.Fatalf("readPin called %d times, want 1", *calls)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestFakeCard_WrongPINIsAuthError(t *testing.T) {
	for _, pin := range []string{"000000", "1234567", "", "12345"} {
		readPin, _ := pinReader(pin, nil)
		adapter, _, _ := openYubiKey(readPin)
		_, err := adapter.SignBytes([]byte("x"))
		if !yubikey.IsPINAuthError(err) {
			t.Errorf("pin %q: err = %v, want a PIN auth error", pin, err)
		}
		if n, _ := yubikey.PINRetries(err); n != fakeCardRetries {
			t.Errorf("pin %q: retries = %d, want %d", pin, n, fakeCardRetries)
		}
		if pin != "" && strings.Contains(err.Error(), pin) {
			t.Errorf("error %q contains the PIN", err)
		}
	}
}

func TestFakeCard_ReadPinErrorPropagates(t *testing.T) {
	sentinel := errors.New("prompt failed")
	readPin, _ := pinReader("", sentinel)
	adapter, _, _ := openYubiKey(readPin)
	_, err := adapter.SignBytes([]byte("x"))
	if err == nil || !strings.Contains(err.Error(), "pin prompt: prompt failed") {
		t.Fatalf("err = %v, want the readPin error in the message", err)
	}
	// Like piv-go, which wraps the prompt error with %v.
	if errors.Is(err, sentinel) || yubikey.IsPINAuthError(err) {
		t.Fatalf("err = %v keeps the readPin error's identity or reads as a PIN error", err)
	}
}

// newFakeCardApp returns an App made by New (so with the default opener) and
// prompter answering pin.
func newFakeCardApp(t *testing.T, pin string) *App {
	t.Helper()
	dir := t.TempDir()
	app, err := New(Config{
		DataDir:       dir,
		Logger:        debuglog.New(filepath.Join(dir, debuglog.FileName)),
		RegistryURL:   "http://127.0.0.1:1",
		RevocationURL: "http://127.0.0.1:1",
		Prompter:      newFakePrompter(pin, false),
		Events:        &fakeEvents{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

func TestFakeCard_AppSignsAndLogs(t *testing.T) {
	app := newFakeCardApp(t, FakeCardPIN)
	fields := SignFields{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"}
	if _, err := app.Sign(context.Background(), fields); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	recs, err := issuancelog.ReadLog(app.LogPath())
	if err != nil || len(recs) != 1 {
		t.Fatalf("log = %v, %v; want one record", recs, err)
	}
	payload, err := core.BuildPayload(fields.request())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(recs[0].SignatureB64URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := FakeCardPublicKey()
	if !ed25519.Verify(pub[:], payload, sig) {
		t.Fatal("logged signature does not verify with the fake card's public key")
	}

	key, err := app.ImportFromYubiKey()
	if err != nil || key != base64.StdEncoding.EncodeToString(pub[:]) {
		t.Fatalf("ImportFromYubiKey = %q, %v", key, err)
	}
}

func TestFakeCard_AppWrongPIN(t *testing.T) {
	app := newFakeCardApp(t, "654321")
	_, err := app.Sign(context.Background(), SignFields{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"})
	var se *SignError
	if !errors.As(err, &se) || !yubikey.IsPINAuthError(err) {
		t.Fatalf("err = %v, want a SignError for a wrong PIN", err)
	}
}

func TestSetPINTimeoutForTest(t *testing.T) {
	app := newFakeCardApp(t, FakeCardPIN)
	if app.pinTimeout != defaultPINEntryTimeout {
		t.Fatalf("default pinTimeout = %v", app.pinTimeout)
	}
	SetPINTimeoutForTest(app, time.Second)
	if app.pinTimeout != time.Second {
		t.Fatalf("pinTimeout = %v, want 1s", app.pinTimeout)
	}
}
