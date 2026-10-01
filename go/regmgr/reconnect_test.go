package regmgr

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

const offlineBtnText = "Offline — Reconnect"

// stubRestoreSession replaces restoreSessionFunc for the duration of the test
// and returns a counter of how many times it was invoked.
func stubRestoreSession(t *testing.T, tok ghapi.Token, user string, loggedIn, offline bool, err error) *atomic.Int32 {
	t.Helper()
	orig := restoreSessionFunc
	t.Cleanup(func() { restoreSessionFunc = orig })
	var calls atomic.Int32
	restoreSessionFunc = func(_ context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		calls.Add(1)
		return tok, user, loggedIn, offline, err
	}
	return &calls
}

// newOfflineTab builds a RegistryTab as a struct literal (the constructor never
// runs, so there is no background restore racing the test) in the
// logged-in-but-offline state.
func newOfflineTab(t *testing.T, fired *atomic.Bool) *RegistryTab {
	t.Helper()
	a := test.NewTempApp(t)
	w := a.NewWindow("test")
	t.Cleanup(w.Close)
	return &RegistryTab{
		state: &appState{
			selected:    -1,
			loggedIn:    true,
			offline:     true,
			githubToken: ghapi.Token{AccessToken: "stored"},
		},
		loginBtn:       widget.NewButton("", nil),
		statusLabel:    widget.NewLabel(""),
		window:         w,
		configDir:      t.TempDir(),
		kr:             ghapi.NewFakeKeyring(),
		onLoginChanged: func() { fired.Store(true) },
	}
}

// waitLoginReleased polls until the reconnect path releases loggingIn — the
// completion signal (and happens-before edge) for the restore callback.
func waitLoginReleased(t *testing.T, rt *RegistryTab) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for rt.loggingIn.Load() {
		if time.Now().After(deadline) {
			t.Fatal("loggingIn was not released within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// HandleUnauthorized
// ---------------------------------------------------------------------------

func TestHandleUnauthorized_ResetsStateAndClearsToken(t *testing.T) {
	rt := newTestRegistryTab(t)
	if err := ghapi.SaveToken(rt.kr, rt.configDir, ghapi.Token{AccessToken: "gho_expired"}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	rt.state.loggedIn = true
	rt.state.offline = true
	rt.state.githubToken = ghapi.Token{AccessToken: "gho_expired"}
	rt.state.githubUser = "octocat"
	var fired bool
	rt.onLoginChanged = func() { fired = true }
	// Prevent startLogin() from spawning a goroutine (no network in tests).
	rt.loggingIn.Store(true)

	rt.HandleUnauthorized()

	if _, err := ghapi.LoadToken(rt.kr, rt.configDir); err == nil {
		t.Error("stored token should be cleared after HandleUnauthorized")
	}
	if rt.state.loggedIn {
		t.Error("loggedIn should be false")
	}
	if rt.state.offline {
		t.Error("offline should be false (a 401 means logged out, not offline)")
	}
	if rt.state.githubToken != (ghapi.Token{}) {
		t.Errorf("githubToken = %+v, want zero value", rt.state.githubToken)
	}
	if rt.state.githubUser != "" {
		t.Errorf("githubUser = %q, want empty", rt.state.githubUser)
	}
	if rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, "Login to GitHub")
	}
	if !fired {
		t.Error("onLoginChanged should fire")
	}
	// Proves startLogin ran: it no-ops with this message because loggingIn is held.
	if rt.statusLabel.Text != "Login already in progress" {
		t.Errorf("statusLabel = %q, want %q (startLogin not called)", rt.statusLabel.Text, "Login already in progress")
	}
}

func TestHandleSubmitError_UnauthorizedClearsOffline(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.loggedIn = true
	rt.state.offline = true
	rt.loggingIn.Store(true)

	rt.handleSubmitError(&ghapi.APIError{StatusCode: 401, Message: "Bad credentials"})

	if rt.state.offline {
		t.Error("offline should be reset by the 401 path")
	}
}

// ---------------------------------------------------------------------------
// StartLoginOrReconnect / restoreSession
// ---------------------------------------------------------------------------

func TestStartLoginOrReconnect_ReconnectSuccess(t *testing.T) {
	calls := stubRestoreSession(t, ghapi.Token{AccessToken: "t"}, "someuser", true, false, nil)
	var fired atomic.Bool
	rt := newOfflineTab(t, &fired)

	rt.StartLoginOrReconnect()
	waitLoginReleased(t, rt)

	if n := calls.Load(); n != 1 {
		t.Errorf("restoreSessionFunc called %d times, want 1", n)
	}
	if rt.ClientForHistory() == nil {
		t.Error("ClientForHistory() = nil, want client after successful reconnect")
	}
	if rt.state.offline {
		t.Error("offline should be false after successful reconnect")
	}
	if !fired.Load() {
		t.Error("onLoginChanged should fire")
	}
	if want := "Reconnected as @someuser."; rt.statusLabel.Text != want {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, want)
	}
	if !strings.HasPrefix(rt.loginBtn.Text, "@someuser") {
		t.Errorf("loginBtn.Text = %q, want prefix %q", rt.loginBtn.Text, "@someuser")
	}
}

func TestStartLoginOrReconnect_StillOffline(t *testing.T) {
	stubRestoreSession(t, ghapi.Token{AccessToken: "stored"}, "", true, true, errors.New("dial tcp: no route"))
	var fired atomic.Bool
	rt := newOfflineTab(t, &fired)

	rt.StartLoginOrReconnect()
	waitLoginReleased(t, rt)

	if !rt.state.offline {
		t.Error("offline should remain true")
	}
	if !rt.state.loggedIn {
		t.Error("loggedIn should remain true")
	}
	if rt.ClientForHistory() != nil {
		t.Error("ClientForHistory() should be nil while offline")
	}
	if rt.loginBtn.Text != offlineBtnText {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, offlineBtnText)
	}
	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty", rt.statusLabel.Text)
	}
}

func TestStartLoginOrReconnect_AlreadyInProgress(t *testing.T) {
	calls := stubRestoreSession(t, ghapi.Token{AccessToken: "t"}, "someuser", true, false, nil)
	var fired atomic.Bool
	rt := newOfflineTab(t, &fired)
	rt.loggingIn.Store(true)

	rt.StartLoginOrReconnect()

	if n := calls.Load(); n != 0 {
		t.Errorf("restoreSessionFunc called %d times, want 0 while login in progress", n)
	}
	if !rt.loggingIn.Load() {
		t.Error("loggingIn should remain held by the in-progress operation")
	}
	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want unchanged (empty)", rt.statusLabel.Text)
	}
}

func TestStartLoginOrReconnect_NotOfflineStartsLogin(t *testing.T) {
	calls := stubRestoreSession(t, ghapi.Token{}, "", false, false, nil)
	rt := newTestRegistryTab(t)
	// Hold loggingIn so startLogin() is observable but spawns no network goroutine.
	rt.loggingIn.Store(true)

	rt.StartLoginOrReconnect()

	if n := calls.Load(); n != 0 {
		t.Errorf("restoreSessionFunc called %d times, want 0 when not offline", n)
	}
	if rt.statusLabel.Text != "Login already in progress" {
		t.Errorf("statusLabel = %q, want startLogin's %q", rt.statusLabel.Text, "Login already in progress")
	}
}

func TestRestoreSession_NonInteractive(t *testing.T) {
	calls := stubRestoreSession(t, ghapi.Token{AccessToken: "t"}, "someuser", true, false, nil)
	var fired atomic.Bool
	rt := newOfflineTab(t, &fired)
	rt.statusLabel.SetText("Fetching...")

	rt.restoreSession(false)

	deadline := time.Now().Add(2 * time.Second)
	for !fired.Load() {
		if time.Now().After(deadline) {
			t.Fatal("restore callback did not run within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if n := calls.Load(); n != 1 {
		t.Errorf("restoreSessionFunc called %d times, want 1", n)
	}
	if rt.ClientForHistory() == nil {
		t.Error("ClientForHistory() = nil, want client after restore")
	}
	// Silent restore must not touch the status label or loggingIn.
	if rt.statusLabel.Text != "Fetching..." {
		t.Errorf("statusLabel = %q, want unchanged %q", rt.statusLabel.Text, "Fetching...")
	}
	if rt.loggingIn.Load() {
		t.Error("loggingIn should not be acquired by a non-interactive restore")
	}
}

func TestSubmitForReview_OfflineReconnectsInsteadOfSubmitting(t *testing.T) {
	calls := stubRestoreSession(t, ghapi.Token{AccessToken: "stored"}, "", true, true, nil)
	var fired atomic.Bool
	rt := newOfflineTab(t, &fired)
	rt.state.registry = core.Registry{Keys: []core.KeyEntry{{Authority: "A"}}}

	rt.submitForReview()
	waitLoginReleased(t, rt)

	if n := calls.Load(); n != 1 {
		t.Errorf("restoreSessionFunc called %d times, want 1 (reconnect)", n)
	}
	if !rt.state.offline {
		t.Error("state should still be offline after a failed reconnect")
	}
}
