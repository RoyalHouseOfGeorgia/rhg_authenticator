package gui

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// ErrSigningCancelled is returned when the user dismisses the PIN dialog.
// This is a normal outcome, not an error — the sign flow should show a
// neutral status message rather than an error.
var ErrSigningCancelled = errors.New("signing cancelled")

// pivMaxPINBytes is the PIV VERIFY command's PIN byte limit (piv-go encodePIN).
const pivMaxPINBytes = 8

// truncatePINToBytes returns the longest prefix of s whose UTF-8 encoding is
// <= maxBytes, cut on a rune boundary so the result is always valid UTF-8.
func truncatePINToBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

// applyPINByteCap wires an OnChanged handler that caps the entry to
// pivMaxPINBytes. SetText re-fires OnChanged once with the capped (<=8-byte)
// string; truncatePINToBytes is idempotent so the re-fire is a no-op — no loop.
func applyPINByteCap(entry *widget.Entry) {
	entry.OnChanged = func(s string) {
		if capped := truncatePINToBytes(s, pivMaxPINBytes); capped != s {
			entry.SetText(capped)
		}
	}
}

// MakePinReader returns a function compatible with YubiKeyAdapter's readPin
// callback. It checks the PinCache first, and if no cached PIN is available,
// shows a modal PIN dialog on the Fyne UI thread and blocks until the user
// responds. This is safe to call from a non-UI goroutine.
func MakePinReader(window fyne.Window, cache *yubikey.PinCache) func() (string, error) {
	return func() (string, error) {
		// Check cache first.
		if pin, ok := cache.Get(); ok {
			return pin, nil
		}

		resultCh := make(chan string, 1)
		errCh := make(chan error, 1)

		fyne.Do(func() {
			showPinDialog(window, cache, resultCh, errCh)
		})

		select {
		case pin := <-resultCh:
			return processPINResult(pin, cache)
		case err := <-errCh:
			return "", err
		case <-time.After(5 * time.Minute):
			return "", fmt.Errorf("PIN entry timed out")
		}
	}
}

// processPINResult applies cancel/cap/cache semantics to a PIN submitted from the
// dialog. An empty submission means the user cancelled. The PIN is capped to the PIV
// byte limit BEFORE it is cached, so the cache only ever stores a valid-length value
// and later cache hits return an already-capped PIN. A cache-set failure is surfaced
// (not swallowed) so the user restarts instead of signing with an unprotected PIN.
func processPINResult(pin string, cache *yubikey.PinCache) (string, error) {
	if pin == "" {
		return "", ErrSigningCancelled
	}
	pin = truncatePINToBytes(pin, pivMaxPINBytes)
	if cache.Enabled() {
		if err := cache.Set(pin); err != nil {
			return "", fmt.Errorf("cannot secure PIN in memory — please restart the app")
		}
	}
	return pin, nil
}

// showPinDialog displays a modal PIN entry dialog. Must be called on the UI thread.
func showPinDialog(window fyne.Window, cache *yubikey.PinCache, resultCh chan<- string, errCh chan<- error) {
	pinEntry := widget.NewPasswordEntry()
	pinEntry.SetPlaceHolder("YubiKey PIN")
	applyPINByteCap(pinEntry)

	rememberCheck := widget.NewCheck("Remember PIN for this session", nil)
	rememberCheck.SetChecked(cache.Enabled())

	content := container.NewVBox(
		widget.NewLabel("Enter your YubiKey PIN to sign:"),
		pinEntry,
		widget.NewLabel("Up to 8 characters"),
		rememberCheck,
	)

	d := dialog.NewCustomConfirm("YubiKey PIN", "OK", "Cancel", content,
		func(confirmed bool) {
			if !confirmed {
				resultCh <- ""
				return
			}
			cache.SetEnabled(rememberCheck.Checked)
			resultCh <- pinEntry.Text
		}, window)
	d.Show()
}
