package regmgr

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

type nopPrompter struct{}

func (nopPrompter) RequestPIN(context.Context, bool) (string, bool, error) { return "", false, nil }

// registryServer serves a one-entry registry.
func registryServer(t *testing.T) string {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := `{"keys":[{"authority":"Auth A","from":"2025-01-01","to":null,"algorithm":"Ed25519","public_key":"` + key + `","note":"n","allowed_honors":["Other"]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newTestRegistryTab builds a RegistryTab on a real service.App (fake keyring,
// no saved session) after Start's restore and fetch from registryURL have
// finished. Login is stubbed: each call sends on the returned channel.
func newTestRegistryTab(t *testing.T, registryURL string) (*RegistryTab, chan struct{}) {
	t.Helper()
	a := test.NewTempApp(t)
	a.Settings().SetTheme(theme.DefaultTheme()) // the test theme has no bold monospace font
	w := a.NewWindow("test")
	t.Cleanup(w.Close)

	events := gui.NewEvents()
	started := make(chan struct{})
	var once sync.Once
	events.On(service.EventRegistryChanged, func(any) { once.Do(func() { close(started) }) })
	svc, err := service.New(service.Config{
		DataDir:     t.TempDir(),
		RegistryURL: registryURL,
		Keyring:     ghapi.NewFakeKeyring(),
		Prompter:    nopPrompter{},
		Events:      events,
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(svc.Close)
	svc.Start()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("startup fetch did not finish")
	}

	rt := NewRegistryTab(svc, events, w)
	logins := make(chan struct{}, 10)
	rt.login = func() { logins <- struct{}{} }
	return rt, logins
}

// overlayHasText reports whether any label or text in o's object tree reads want.
func overlayHasText(o fyne.CanvasObject, want string) bool {
	for _, obj := range test.LaidOutObjects(o) {
		switch v := obj.(type) {
		case *widget.Label:
			if v.Text == want {
				return true
			}
		case *canvas.Text:
			if v.Text == want {
				return true
			}
		}
	}
	return false
}

// topOverlay returns the window's top overlay, failing if there is none.
func topOverlay(t *testing.T, rt *RegistryTab) fyne.CanvasObject {
	t.Helper()
	top := rt.window.Canvas().Overlays().Top()
	if top == nil {
		t.Fatal("no dialog shown")
	}
	return top
}

// findButton returns the button labelled text in o's object tree.
func findButton(t *testing.T, o fyne.CanvasObject, text string) *widget.Button {
	t.Helper()
	for _, obj := range test.LaidOutObjects(o) {
		if b, ok := obj.(*widget.Button); ok && b.Text == text {
			return b
		}
	}
	t.Fatalf("button %q not found", text)
	return nil
}
