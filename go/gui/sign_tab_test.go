package gui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// TestOnSaveQRChosen covers the QR save callback: dismissed, save-dialog
// error, success, and a failed write.
func TestOnSaveQRChosen(t *testing.T) {
	test.NewTempApp(t)
	w := test.NewWindow(nil)
	w.Resize(fyne.NewSize(800, 600))
	t.Cleanup(w.Close)
	svc := newTestApp(t, NewEvents(), &cancelPrompter{})
	const url = "https://verify.example.org/?p=abc&s=def"

	onSaveQRChosen(svc, w, url, "svg", nil, nil)
	if top := w.Canvas().Overlays().Top(); top != nil {
		t.Fatal("dismissed save dialog showed an overlay")
	}

	assertSaveError := func(what string) {
		t.Helper()
		texts := strings.ToLower(strings.Join(labelTexts(t, topOverlay(t, w)), "\n"))
		if !strings.Contains(texts, "could not save the "+what) {
			t.Errorf("save error for %q not shown:\n%s", what, texts)
		}
		tapOverlayButton(t, w, "OK")
	}

	// Fyne reports an uncreatable destination as a writer plus a non-nil error.
	onSaveQRChosen(svc, w, url, "svg", &fakeURIWriter{}, errors.New("boom"))
	assertSaveError("svg file")

	path := filepath.Join(t.TempDir(), "q.png")
	wr := &fakeURIWriter{path: path}
	onSaveQRChosen(svc, w, url, "png", wr, nil)
	if !wr.closed {
		t.Error("writer not closed")
	}
	if data, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(data), "\x89PNG") {
		t.Errorf("PNG not written: %v", err)
	}
	if top := w.Canvas().Overlays().Top(); top != nil {
		t.Error("successful save showed an overlay")
	}

	onSaveQRChosen(svc, w, url, "png", &fakeURIWriter{path: filepath.Join(t.TempDir(), "missing", "q.png")}, nil)
	assertSaveError("png file")
}
