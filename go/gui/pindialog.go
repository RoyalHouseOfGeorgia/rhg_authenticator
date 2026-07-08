package gui

import (
	"errors"
	"fmt"
	"sync/atomic"
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

// ErrPINEntryTimedOut is returned when the PIN dialog is left unanswered past
// the timeout. Like ErrSigningCancelled it is a neutral outcome. It is a typed
// sentinel (matched via errors.Is) rather than a free-text error because the
// literal string "PIN entry timed out" matches core.ClassifyHardwareError's
// \bpin\b regex and would otherwise be misclassified as a hardware PIN error.
var ErrPINEntryTimedOut = errors.New("PIN entry timed out")

// ErrPINCacheUnavailable is returned when the PIN cannot be secured in mlock'd
// memory. Same misclassification hazard as ErrPINEntryTimedOut — matched via
// errors.Is, so it MUST be returned bare or %w-wrapped (never %v-joined).
var ErrPINCacheUnavailable = errors.New("cannot secure PIN in memory")

// defaultPINEntryTimeout is the deadline for PIN dialog entry. Balances a
// multi-sign session against an unattended workstation.
const defaultPINEntryTimeout = 5 * time.Minute

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
	return makePinReaderWithTimeout(window, cache, defaultPINEntryTimeout)
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
			return processPINResult(pin, cache)
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
			return "", ErrPINEntryTimedOut
		}
	}
}

// processPINResult applies cancel/cap/cache semantics to a PIN submitted from the
// dialog. An empty submission means the user cancelled. The PIN is capped to the PIV
// byte limit BEFORE it is cached, so the cache only ever stores a valid-length value
// and later cache hits return an already-capped PIN. A cache-set failure is surfaced
// (not swallowed) so the user restarts instead of signing with an unprotected PIN.
//
// The PIN is cached here, before the card validates it. Only a later piv.AuthErr
// clears it (via clearPINCacheOnAuthError); a non-auth failure (no key, cert read,
// or a transient PC/SC reset) leaves the entered PIN cached until the timeout.
// Accepted tradeoff: if that PIN was mistyped it is replayed once on the next
// sign, costing a single PIV retry before the resulting AuthErr clears it —
// bounded, self-healing, and not attacker-drivable on a single-operator desktop.
// Clearing on every non-auth failure was rejected: it would force PIN re-entry
// after a transient reset, defeating this flow's retry-without-re-prompt goal.
func processPINResult(pin string, cache *yubikey.PinCache) (string, error) {
	if pin == "" {
		return "", ErrSigningCancelled
	}
	pin = truncatePINToBytes(pin, pivMaxPINBytes)
	if cache.Enabled() {
		if err := cache.Set(pin); err != nil {
			// %w so signFlowErrorMessage can match ErrPINCacheUnavailable via
			// errors.Is (a %v join would fall into the \bpin\b misclassification).
			return "", fmt.Errorf("%w: %v", ErrPINCacheUnavailable, err)
		}
	}
	return pin, nil
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
