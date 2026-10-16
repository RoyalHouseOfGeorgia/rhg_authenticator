package gui

import (
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/yubikey"
)

// applyPINByteCap wires an OnChanged handler that caps the entry to
// service.PIVMaxPINBytes. SetText re-fires OnChanged once with the capped (<=8-byte)
// string; service.TruncatePINToBytes is idempotent so the re-fire is a no-op — no loop.
func applyPINByteCap(entry *widget.Entry) {
	entry.OnChanged = func(s string) {
		if capped := service.TruncatePINToBytes(s, service.PIVMaxPINBytes); capped != s {
			entry.SetText(capped)
		}
	}
}

// MakePinReader returns a function compatible with YubiKeyAdapter's readPin
// callback. It checks the PinCache first, and if no cached PIN is available,
// shows a modal PIN dialog on the Fyne UI thread and blocks until the user
// responds. This is safe to call from a non-UI goroutine.
func MakePinReader(window fyne.Window, cache *yubikey.PinCache) func() (string, error) {
	return makePinReaderWithTimeout(window, cache, service.DefaultPINEntryTimeout)
}

// makePinReaderWithTimeout is MakePinReader with an injectable timeout for tests.
func makePinReaderWithTimeout(window fyne.Window, cache *yubikey.PinCache, timeout time.Duration) func() (string, error) {
	return func() (string, error) {
		// Check cache first.
		if pin, ok := cache.Get(); ok {
			return pin, nil
		}

		resultCh := make(chan string, 1)
		// settled guards the confirm callback against a late submit after the
		// timeout has already fired (and vice versa).
		var settled atomic.Bool
		var dlg dialog.Dialog

		fyne.Do(func() {
			dlg = showPinDialog(window, cache, resultCh, &settled)
		})

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case pin := <-resultCh:
			return service.ProcessPINResult(pin, cache)
		case <-timer.C:
			settled.Store(true)
			// dlg is written and read only inside fyne.Do closures (one UI
			// thread, FIFO) — the assignment above is enqueued before this Hide,
			// so no data race despite the two goroutines.
			fyne.Do(func() {
				if dlg != nil {
					dlg.Hide()
				}
			})
			return "", service.ErrPINEntryTimedOut
		}
	}
}

// showPinDialog displays a modal PIN entry dialog and returns its handle so the
// caller can Hide() it on timeout. Must be called on the UI thread.
func showPinDialog(window fyne.Window, cache *yubikey.PinCache, resultCh chan<- string, settled *atomic.Bool) dialog.Dialog {
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
		pinConfirmHandler(settled, cache, resultCh, pinEntry, rememberCheck), window)
	d.Show()
	return d
}

// pinConfirmHandler builds the confirm callback for the PIN dialog. Extracted so
// the settled-gate is unit-testable without driving the Fyne dialog. The
// settled.Swap(true) guard ensures a late submit (after the reader already timed
// out) is ignored: it neither flips the remember preference nor sends a PIN.
func pinConfirmHandler(settled *atomic.Bool, cache *yubikey.PinCache, resultCh chan<- string, entry *widget.Entry, remember *widget.Check) func(bool) {
	return func(confirmed bool) {
		if settled.Swap(true) {
			return
		}
		if !confirmed {
			resultCh <- ""
			return
		}
		cache.SetEnabled(remember.Checked)
		resultCh <- entry.Text
	}
}
