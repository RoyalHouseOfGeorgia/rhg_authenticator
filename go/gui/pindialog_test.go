package gui

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// TestShowPinDialog_Renders gives showPinDialog's rendering path positive
// coverage: after it runs, a modal overlay is present on the canvas. Paired with
// TestPrompter_Timeout (which covers close-on-timeout), this proves the full
// show→hide lifecycle — neither test alone can.
func TestShowPinDialog_Renders(t *testing.T) {
	test.NewApp()
	w := test.NewWindow(nil)
	defer w.Close()

	resultCh := make(chan pinResult, 1)
	var settled atomic.Bool

	var dlg dialog.Dialog
	fyne.Do(func() { dlg = showPinDialog(w, true, resultCh, &settled) })
	if dlg == nil {
		t.Fatal("showPinDialog returned nil dialog")
	}
	if top := w.Canvas().Overlays().Top(); top == nil {
		t.Error("expected the PIN dialog to render an overlay, got none")
	}
}

// TestPrompter_Timeout covers the ctx-done path: when the dialog is left
// unanswered past the ctx deadline, RequestPIN returns and leaves no lingering
// overlay (dlg.Hide ran). RequestPIN runs synchronously on the test goroutine;
// Fyne's test driver runs fyne.Do inline, so Hide completes before the call
// returns (a goroutine reading Overlays() concurrently would data-race the
// overlay stack under -race).
func TestPrompter_Timeout(t *testing.T) {
	test.NewApp()
	w := test.NewWindow(nil)
	defer w.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	pin, remember, err := NewPrompter(w).RequestPIN(ctx, false)
	if !errors.Is(err, context.DeadlineExceeded) || pin != "" || remember {
		t.Fatalf("RequestPIN = %q, %v, %v; want ctx deadline error", pin, remember, err)
	}
	if top := w.Canvas().Overlays().Top(); top != nil {
		t.Errorf("expected dialog closed on timeout, overlay still present: %T", top)
	}
}

// TestPinConfirmHandler_Confirm: a normal confirm sends the entered PIN and
// the remember choice.
func TestPinConfirmHandler_Confirm(t *testing.T) {
	resultCh := make(chan pinResult, 1)
	entry := widget.NewEntry()
	entry.SetText("1234")
	remember := widget.NewCheck("", nil)
	remember.SetChecked(true)
	var settled atomic.Bool

	pinConfirmHandler(&settled, resultCh, entry, remember)(true)

	select {
	case got := <-resultCh:
		if got != (pinResult{pin: "1234", remember: true}) {
			t.Errorf("got %+v, want {1234 true}", got)
		}
	default:
		t.Fatal("expected PIN on resultCh")
	}
}

// TestPinConfirmHandler_Cancel: a dismiss sends the empty-PIN cancel signal.
func TestPinConfirmHandler_Cancel(t *testing.T) {
	resultCh := make(chan pinResult, 1)
	entry := widget.NewEntry()
	entry.SetText("1234")
	remember := widget.NewCheck("", nil)
	var settled atomic.Bool

	pinConfirmHandler(&settled, resultCh, entry, remember)(false)

	select {
	case got := <-resultCh:
		if got.pin != "" {
			t.Errorf("got pin %q, want empty (cancel)", got.pin)
		}
	default:
		t.Fatal("expected a cancel on resultCh")
	}
}

// TestPinConfirmHandler_LateSubmitIgnored: a confirm after RequestPIN already
// settled must not send anything.
func TestPinConfirmHandler_LateSubmitIgnored(t *testing.T) {
	resultCh := make(chan pinResult, 1)
	entry := widget.NewEntry()
	entry.SetText("1234")
	remember := widget.NewCheck("", nil)
	remember.SetChecked(true)
	var settled atomic.Bool
	settled.Store(true) // ctx already done

	pinConfirmHandler(&settled, resultCh, entry, remember)(true)

	select {
	case got := <-resultCh:
		t.Fatalf("expected no send after settle, got %+v", got)
	default:
	}
}

// TestApplyPINByteCap verifies the OnChanged handler caps a real widget entry
// to 8 bytes without producing invalid UTF-8 or looping.
func TestApplyPINByteCap(t *testing.T) {
	test.NewApp()

	entry := widget.NewPasswordEntry()
	applyPINByteCap(entry)

	entry.SetText("123456789")
	if entry.Text != "12345678" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "12345678")
	}

	entry.SetText("café1234")
	if len(entry.Text) > service.PIVMaxPINBytes || !utf8.ValidString(entry.Text) {
		t.Errorf("invariant violated: entry.Text = %q (%d bytes, valid=%v)",
			entry.Text, len(entry.Text), utf8.ValidString(entry.Text))
	}
	if entry.Text != "café123" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "café123")
	}
}

// TestApplyPINByteCap_RuneSplitBoundary drives the utf8.RuneStart back-off end-to-end
// through the real widget's OnChanged/SetText: a trailing multibyte rune that would
// straddle the 8-byte limit must be dropped whole, not split.
func TestApplyPINByteCap_RuneSplitBoundary(t *testing.T) {
	test.NewApp()

	entry := widget.NewPasswordEntry()
	applyPINByteCap(entry)

	entry.SetText("1234567é")
	if entry.Text != "1234567" {
		t.Errorf("after cap, entry.Text = %q, want %q", entry.Text, "1234567")
	}
}
