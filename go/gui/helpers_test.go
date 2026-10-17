package gui

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// findButton walks obj (containers and widget renderers) and returns the
// first button labelled text, or nil.
func findButton(t *testing.T, obj fyne.CanvasObject, text string) *widget.Button {
	t.Helper()
	switch o := obj.(type) {
	case *widget.Button:
		if o.Text == text {
			return o
		}
		return nil
	case *fyne.Container:
		for _, child := range o.Objects {
			if b := findButton(t, child, text); b != nil {
				return b
			}
		}
		return nil
	case fyne.Widget:
		for _, child := range test.TempWidgetRenderer(t, o).Objects() {
			if b := findButton(t, child, text); b != nil {
				return b
			}
		}
	}
	return nil
}

// labelTexts collects the text of every label under obj.
func labelTexts(t *testing.T, obj fyne.CanvasObject) []string {
	var out []string
	switch o := obj.(type) {
	case *widget.Label:
		return []string{o.Text}
	case *fyne.Container:
		for _, child := range o.Objects {
			out = append(out, labelTexts(t, child)...)
		}
	case fyne.Widget:
		for _, child := range test.TempWidgetRenderer(t, o).Objects() {
			out = append(out, labelTexts(t, child)...)
		}
	}
	return out
}

func topOverlay(t *testing.T, w fyne.Window) fyne.CanvasObject {
	t.Helper()
	top := w.Canvas().Overlays().Top()
	if top == nil {
		t.Fatal("expected a dialog overlay, got none")
	}
	return top
}

func tapOverlayButton(t *testing.T, w fyne.Window, text string) {
	t.Helper()
	b := findButton(t, topOverlay(t, w), text)
	if b == nil {
		t.Fatalf("no %q button in top overlay", text)
	}
	test.Tap(b)
}

// cancelPrompter answers every PIN request with a cancel, unless onRequest
// is set, in which case it runs first with the request's ctx.
type cancelPrompter struct {
	calls     int
	onRequest func(ctx context.Context)
}

func (p *cancelPrompter) RequestPIN(ctx context.Context, rememberDefault bool) (string, bool, error) {
	p.calls++
	if p.onRequest != nil {
		p.onRequest(ctx)
	}
	return "", false, nil
}

// newTestApp returns a service.App on a temp DataDir with an unreachable
// registry (offline), wired to events and prompter.
func newTestApp(t *testing.T, events *Events, prompter service.Prompter) *service.App {
	t.Helper()
	dir := t.TempDir()
	app, err := service.New(service.Config{
		DataDir:     dir,
		Logger:      debuglog.New(filepath.Join(dir, debuglog.FileName)),
		RegistryURL: "http://127.0.0.1:1",
		Prompter:    prompter,
		Events:      events,
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// fakeURIWriter is a fyne.URIWriteCloser whose URI points at path. Exports
// that write by path (bulk results) ignore buf; the issuance-log export writes
// through Write into buf. failWrite / failClose make Write / Close fail.
type fakeURIWriter struct {
	path      string
	buf       bytes.Buffer
	failWrite bool
	failClose bool
	closed    bool
}

func (f *fakeURIWriter) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("write failed")
	}
	return f.buf.Write(p)
}

func (f *fakeURIWriter) Close() error {
	f.closed = true
	if f.failClose {
		return errors.New("close failed")
	}
	return nil
}

func (f *fakeURIWriter) URI() fyne.URI { return storage.NewFileURI(f.path) }
