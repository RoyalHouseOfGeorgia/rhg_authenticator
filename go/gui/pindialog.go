package gui

import (
	"errors"
	"fmt"
	"time"

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
			if pin == "" {
				return "", ErrSigningCancelled
			}
			if cache.Enabled() {
				if err := cache.Set(pin); err != nil {
					return "", fmt.Errorf("cannot secure PIN in memory — please restart the app")
				}
			}
			return pin, nil
		case err := <-errCh:
			return "", err
		case <-time.After(5 * time.Minute):
			return "", fmt.Errorf("PIN entry timed out")
		}
	}
}

// showPinDialog displays a modal PIN entry dialog. Must be called on the UI thread.
func showPinDialog(window fyne.Window, cache *yubikey.PinCache, resultCh chan<- string, errCh chan<- error) {
	pinEntry := widget.NewPasswordEntry()
	pinEntry.SetPlaceHolder("YubiKey PIN")

	rememberCheck := widget.NewCheck("Remember PIN for this session", nil)
	rememberCheck.SetChecked(cache.Enabled())

	content := container.NewVBox(
		widget.NewLabel("Enter your YubiKey PIN to sign:"),
		pinEntry,
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
