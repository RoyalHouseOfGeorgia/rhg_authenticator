package gui

import (
	"context"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
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

// pinResult is a PIN dialog submission. An empty pin means Cancel.
type pinResult struct {
	pin      string
	remember bool
}

// fynePrompter shows the PIN dialog on window.
type fynePrompter struct{ window fyne.Window }

// NewPrompter returns a service.Prompter that shows a modal PIN dialog on
// window. RequestPIN blocks and must not be called on the UI thread.
func NewPrompter(window fyne.Window) service.Prompter {
	return &fynePrompter{window: window}
}

// RequestPIN shows the PIN dialog and waits for a submission or ctx.Done(),
// in which case the dialog is hidden.
func (p *fynePrompter) RequestPIN(ctx context.Context, rememberDefault bool) (string, bool, error) {
	resultCh := make(chan pinResult, 1)
	// settled guards the confirm callback against a late submit after ctx is
	// done (and vice versa): dialog.Hide() re-runs the callback, which would
	// otherwise block the UI thread on the full channel.
	var settled atomic.Bool
	var dlg dialog.Dialog

	fyne.Do(func() {
		dlg = showPinDialog(p.window, rememberDefault, resultCh, &settled)
	})

	select {
	case r := <-resultCh:
		return r.pin, r.remember, nil
	case <-ctx.Done():
		settled.Store(true)
		// dlg is written and read only inside fyne.Do closures (one UI
		// thread, FIFO) — the assignment above is enqueued before this Hide,
		// so no data race despite the two goroutines.
		fyne.Do(func() {
			if dlg != nil {
				dlg.Hide()
			}
		})
		return "", false, ctx.Err()
	}
}

// showPinDialog displays a modal PIN entry dialog and returns its handle so the
// caller can Hide() it. Must be called on the UI thread.
func showPinDialog(window fyne.Window, rememberDefault bool, resultCh chan<- pinResult, settled *atomic.Bool) dialog.Dialog {
	pinEntry := widget.NewPasswordEntry()
	pinEntry.SetPlaceHolder("YubiKey PIN")
	applyPINByteCap(pinEntry)

	rememberCheck := widget.NewCheck("Remember PIN for this session", nil)
	rememberCheck.SetChecked(rememberDefault)

	content := container.NewVBox(
		widget.NewLabel("Enter your YubiKey PIN to sign:"),
		pinEntry,
		widget.NewLabel("Up to 8 characters"),
		rememberCheck,
	)

	d := dialog.NewCustomConfirm("YubiKey PIN", "OK", "Cancel", content,
		pinConfirmHandler(settled, resultCh, pinEntry, rememberCheck), window)
	d.Show()
	return d
}

// pinConfirmHandler builds the confirm callback for the PIN dialog. Extracted so
// the settled-gate is unit-testable without driving the Fyne dialog. The
// settled.Swap(true) guard ensures a late submit (after RequestPIN already
// returned) is ignored.
func pinConfirmHandler(settled *atomic.Bool, resultCh chan<- pinResult, entry *widget.Entry, remember *widget.Check) func(bool) {
	return func(confirmed bool) {
		if settled.Swap(true) {
			return
		}
		if !confirmed {
			resultCh <- pinResult{}
			return
		}
		resultCh <- pinResult{pin: entry.Text, remember: remember.Checked}
	}
}
