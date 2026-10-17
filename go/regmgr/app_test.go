package regmgr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"

	"fyne.io/fyne/v2/test"
)

const unreachable = "http://127.0.0.1:1"

func TestTableColumnWidths(t *testing.T) {
	if len(service.RegistryColumns) != len(tableColumnWidths) {
		t.Errorf("RegistryColumns (%d) and tableColumnWidths (%d) length mismatch",
			len(service.RegistryColumns), len(tableColumnWidths))
	}
}

func TestNewRegistryTab_LoadedAtStartup(t *testing.T) {
	rt, _ := newTestRegistryTab(t, registryServer(t))
	if rt.statusLabel.Text != "Loaded from registry server" {
		t.Errorf("status = %q", rt.statusLabel.Text)
	}
	if rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("loginBtn = %q", rt.loginBtn.Text)
	}
	if rows, cols := rt.table.Length(); rows != 2 || cols != len(service.RegistryColumns) {
		t.Errorf("table = %dx%d, want 2x%d", rows, cols, len(service.RegistryColumns))
	}
	if got := rt.snap.Rows[0][1]; got != "Auth A" {
		t.Errorf("authority cell = %q", got)
	}
}

func TestRegistryChanged(t *testing.T) {
	t.Run("loaded", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, registryServer(t))
		rt.selected = 0
		rt.registryChanged()
		if rt.statusLabel.Text != "Loaded from registry server" || rt.selected != -1 {
			t.Errorf("status = %q, selected = %d", rt.statusLabel.Text, rt.selected)
		}
		if rows, _ := rt.table.Length(); rows != 2 {
			t.Errorf("table rows = %d, want header + 1", rows)
		}
	})
	t.Run("failed", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, unreachable)
		rt.selected = 3
		rt.registryChanged()
		if rt.statusLabel.Text != "Failed to load registry" || rt.selected != -1 {
			t.Errorf("status = %q, selected = %d", rt.statusLabel.Text, rt.selected)
		}
	})
}

func TestUpdateLoginUI(t *testing.T) {
	rt, _ := newTestRegistryTab(t, unreachable)
	for _, tc := range []struct {
		st   service.AuthState
		want string
	}{
		{service.AuthState{}, "Login to GitHub"},
		{service.AuthState{LoggedIn: true, Offline: true}, "Offline — Reconnect"},
		{service.AuthState{LoggedIn: true, User: "octocat"}, "@octocat ▾"},
	} {
		rt.UpdateLoginUI(tc.st)
		if rt.loginBtn.Text != tc.want {
			t.Errorf("%+v: loginBtn = %q, want %q", tc.st, rt.loginBtn.Text, tc.want)
		}
	}
}

// The tab leaves EventAuthChanged to the host; a host handler calling
// UpdateLoginUI (as main registers it) sees every login-state change.
func TestAuthChangedEvent_HostHandler(t *testing.T) {
	rt, _, events := newTestRegistryTabWithEvents(t, unreachable)
	rt.loginBtn.SetText("stale")
	rt.svc.Logout()
	if rt.loginBtn.Text != "stale" {
		t.Fatalf("the tab handled EventAuthChanged itself: loginBtn = %q", rt.loginBtn.Text)
	}

	fired := 0
	events.On(service.EventAuthChanged, func(any) { fired++; rt.UpdateLoginUI(rt.svc.AuthState()) })
	rt.svc.Logout()
	if fired != 1 || rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("fired = %d, loginBtn = %q", fired, rt.loginBtn.Text)
	}
}

func TestStartLogin(t *testing.T) {
	for _, tc := range []struct {
		st   service.AuthState
		want string
	}{
		{service.AuthState{}, "Requesting device code..."},
		{service.AuthState{LoggedIn: true, Offline: true}, "Reconnecting to GitHub..."},
		{service.AuthState{LoggedIn: true, User: "octocat"}, "Requesting device code..."},
	} {
		rt, logins := newTestRegistryTab(t, unreachable)
		rt.startLogin(tc.st)
		if rt.statusLabel.Text != tc.want || len(logins) != 1 {
			t.Errorf("%+v: status = %q, logins = %d", tc.st, rt.statusLabel.Text, len(logins))
		}
	}

	rt, logins := newTestRegistryTab(t, unreachable)
	rt.StartLogin() // the service is logged out
	if rt.statusLabel.Text != "Requesting device code..." || len(logins) != 1 {
		t.Errorf("StartLogin: status = %q, logins = %d", rt.statusLabel.Text, len(logins))
	}
}

func TestLoginButton_LoggedOutStartsLogin(t *testing.T) {
	rt, logins := newTestRegistryTab(t, unreachable)
	test.Tap(rt.loginBtn)
	if rt.statusLabel.Text != "Requesting device code..." || len(logins) != 1 {
		t.Errorf("status = %q, logins = %d", rt.statusLabel.Text, len(logins))
	}
}

func TestShowLoginDialog(t *testing.T) {
	rt, _ := newTestRegistryTab(t, unreachable)
	rt.showLoginDialog(service.DeviceCode{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"})
	top := topOverlay(t, rt)
	if !overlayHasText(top, "ABCD-1234") || rt.statusLabel.Text != "Waiting for GitHub authorization..." {
		t.Errorf("status = %q", rt.statusLabel.Text)
	}
	if findButton(t, top, "Copy Code").Disabled() || findButton(t, top, "Open GitHub").Disabled() {
		t.Error("buttons disabled for a valid URI")
	}
	test.Tap(findButton(t, top, "Cancel"))
	if rt.loginDialog != nil {
		t.Error("Cancel did not clear the dialog")
	}

	rt.showLoginDialog(service.DeviceCode{UserCode: "WXYZ-0000"})
	top = topOverlay(t, rt)
	if findButton(t, top, "Copy Code").Disabled() || !findButton(t, top, "Open GitHub").Disabled() {
		t.Error("without a verification URI, want Copy Code enabled and Open GitHub disabled")
	}
	rt.hideLoginDialog()
	if rt.loginDialog != nil || rt.window.Canvas().Overlays().Top() == top {
		t.Error("hideLoginDialog did not dismiss the dialog")
	}
	rt.hideLoginDialog() // no dialog: no-op
}

func TestLoginDone(t *testing.T) {
	t.Run("busy keeps the running login's dialog", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, unreachable)
		rt.showLoginDialog(service.DeviceCode{UserCode: "ABCD-1234"})
		rt.loginDone(service.AuthState{}, service.ErrBusy)
		if rt.statusLabel.Text != "Login already in progress" || rt.loginDialog == nil {
			t.Errorf("status = %q, dialog = %v", rt.statusLabel.Text, rt.loginDialog)
		}
	})
	t.Run("cancelled shows no error", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, unreachable)
		rt.showLoginDialog(service.DeviceCode{UserCode: "ABCD-1234"})
		rt.loginDone(service.AuthState{}, fmt.Errorf("login failed: %w", context.Canceled))
		if rt.statusLabel.Text != "" || rt.loginDialog != nil {
			t.Errorf("status = %q", rt.statusLabel.Text)
		}
		if rt.window.Canvas().Overlays().Top() != nil {
			t.Error("a dialog is shown after cancel")
		}
	})
	t.Run("error", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, unreachable)
		rt.loginDone(service.AuthState{}, errors.New("device code request failed: boom"))
		if rt.statusLabel.Text != "" || !overlayHasText(topOverlay(t, rt), "Error") {
			t.Errorf("status = %q", rt.statusLabel.Text)
		}
	})
	t.Run("still offline", func(t *testing.T) {
		rt, logins := newTestRegistryTab(t, unreachable)
		rt.statusLabel.SetText("Reconnecting to GitHub...")
		rt.showLoginDialog(service.DeviceCode{UserCode: "ABCD-1234"})
		rt.loginDone(service.AuthState{LoggedIn: true, Offline: true}, nil)
		if rt.statusLabel.Text != "" || rt.loginDialog != nil || len(logins) != 0 {
			t.Errorf("status = %q, dialog = %v, logins = %d", rt.statusLabel.Text, rt.loginDialog, len(logins))
		}
		if top := topOverlay(t, rt); !overlayHasText(top, "GitHub Unreachable") ||
			!overlayHasText(top, "Still can't reach GitHub. Check your connection and try again.") {
			t.Error("GitHub Unreachable dialog not shown")
		}
	})
	t.Run("outcomes", func(t *testing.T) {
		rt, _ := newTestRegistryTab(t, unreachable)
		for _, tc := range []struct {
			st   service.AuthState
			want string
		}{
			{service.AuthState{LoggedIn: true, User: "octocat"}, "Logged in as @octocat"},
			{service.AuthState{}, "Not logged in"},
		} {
			rt.loginDone(tc.st, nil)
			if rt.statusLabel.Text != tc.want {
				t.Errorf("%+v: status = %q, want %q", tc.st, rt.statusLabel.Text, tc.want)
			}
		}
	})
}

func TestHandleSubmitError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantDialog string
		wantLogins int
	}{
		{"unauthorized", fmt.Errorf("submit: %w", &ghapi.APIError{StatusCode: 401}), "Session Expired", 1},
		{"registry changed", fmt.Errorf("submit: %w", service.ErrRegistryChanged), "Registry Changed", 0},
		{"generic", &ghapi.APIError{StatusCode: 429}, "Submission Failed", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, logins := newTestRegistryTab(t, unreachable)
			rt.statusLabel.SetText("Creating pull request...")
			rt.handleSubmitError(tc.err)
			if !overlayHasText(topOverlay(t, rt), tc.wantDialog) {
				t.Errorf("want the %q dialog", tc.wantDialog)
			}
			if len(logins) != tc.wantLogins {
				t.Errorf("logins = %d, want %d", len(logins), tc.wantLogins)
			}
			wantStatus := ""
			if tc.wantLogins > 0 {
				wantStatus = "Requesting device code..."
			}
			if rt.statusLabel.Text != wantStatus {
				t.Errorf("status = %q, want %q", rt.statusLabel.Text, wantStatus)
			}
		})
	}
}

func TestHandleSubmitSuccess(t *testing.T) {
	for _, u := range []string{"https://github.com/owner/repo/pull/42", "http://insecure.example.com/pull/42", "", "://bad-url"} {
		rt, _ := newTestRegistryTab(t, unreachable)
		rt.handleSubmitSuccess(ghapi.PRResult{Number: 42, HTMLURL: u})
		if rt.statusLabel.Text != "PR #42 created" {
			t.Errorf("%q: status = %q", u, rt.statusLabel.Text)
		}
		want := "PR #42 has been created."
		if strings.HasPrefix(u, "https://") {
			want += "\n\nOpen in browser?"
		}
		if !overlayHasText(topOverlay(t, rt), want) {
			t.Errorf("%q: dialog text %q not shown", u, want)
		}
	}
}

func TestSubmitForReview(t *testing.T) {
	t.Run("empty registry does nothing", func(t *testing.T) {
		rt, logins := newTestRegistryTab(t, unreachable)
		rt.statusLabel.SetText("Failed to load registry")
		rt.submitForReview()
		if rt.statusLabel.Text != "Failed to load registry" || len(logins) != 0 {
			t.Errorf("status = %q, logins = %d", rt.statusLabel.Text, len(logins))
		}
	})
	t.Run("logged out starts login", func(t *testing.T) {
		rt, logins := newTestRegistryTab(t, registryServer(t))
		rt.submitForReview()
		select {
		case <-logins:
		case <-time.After(5 * time.Second):
			t.Fatal("login not started")
		}
	})
}

func TestFetchButton_ConfirmsDiscardingEdits(t *testing.T) {
	rt, _, events := newTestRegistryTabWithEvents(t, registryServer(t))
	if err := rt.svc.AddEntry(service.EntryForm{Authority: "B", From: "2026-01-01", NoExpiry: true}, rt.snap.Entries[0].PublicKey); err != nil {
		t.Fatal(err)
	}
	test.Tap(findButton(t, rt.Content, "Fetch from Server"))
	top := topOverlay(t, rt)
	if !overlayHasText(top, "Discard Local Edits?") {
		t.Fatal("no discard confirm with unsubmitted edits")
	}
	// The refetch runs in the background; wait until its event handler has
	// finished with the widgets before checking or tearing down.
	done := make(chan struct{})
	events.On(service.EventRegistryChanged, func(any) { rt.registryChanged(); close(done) })
	test.Tap(findButton(t, top, "Yes"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refetch did not finish")
	}
	if rt.svc.Dirty() || len(rt.snap.Entries) != 1 || rt.statusLabel.Text != "Loaded from registry server" {
		t.Errorf("edits not discarded: dirty %v, %d entries, status %q", rt.svc.Dirty(), len(rt.snap.Entries), rt.statusLabel.Text)
	}
}

func TestEditDialog_SaveMarksDirty(t *testing.T) {
	rt, _ := newTestRegistryTab(t, registryServer(t))
	showEditDialog(rt.window, rt.svc, 0, rt.snap.Entries[0], rt.refreshTable)
	top := topOverlay(t, rt)
	test.Tap(findButton(t, top, "Save"))
	if !rt.snap.Dirty || !rt.svc.Dirty() {
		t.Error("save did not mark the registry dirty")
	}
	if rt.window.Canvas().Overlays().Top() == top {
		t.Error("dialog still open after a successful save")
	}
}

func TestEditDialog_StaleEntryShowsError(t *testing.T) {
	rt, _ := newTestRegistryTab(t, registryServer(t))
	stale := rt.snap.Entries[0]
	stale.PublicKey = "replaced"
	showEditDialog(rt.window, rt.svc, 0, stale, rt.refreshTable)
	top := topOverlay(t, rt)
	test.Tap(findButton(t, top, "Save"))
	if rt.svc.Dirty() || rt.window.Canvas().Overlays().Top() != top {
		t.Error("stale save was applied or closed the dialog")
	}
	if !overlayHasText(top, "The registry was reloaded while you were editing. Cancel and edit the entry again.") {
		t.Error("stale-entry error not shown")
	}
}

func TestAddDialog_ValidationError(t *testing.T) {
	rt, _ := newTestRegistryTab(t, unreachable)
	showAddDialog(rt.window, rt.svc, rt.refreshTable)
	top := topOverlay(t, rt)
	test.Tap(findButton(t, top, "Add"))
	if !overlayHasText(top, "Authority is required") {
		t.Error("validation error not shown")
	}
	if rt.window.Canvas().Overlays().Top() != top || len(rt.snap.Entries) != 0 {
		t.Error("invalid add closed the dialog or added an entry")
	}
}
