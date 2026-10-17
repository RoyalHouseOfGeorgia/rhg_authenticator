package regmgr

import (
	"errors"
	"net/url"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"

	"fyne.io/fyne/v2/widget"
)

func TestAppState_InitialValues(t *testing.T) {
	state := &appState{selected: -1}
	if state.dirty {
		t.Error("expected dirty = false initially")
	}
	if state.selected != -1 {
		t.Errorf("expected selected = -1 initially, got %d", state.selected)
	}
	if len(state.registry.Keys) != 0 {
		t.Errorf("expected empty registry initially, got %d keys", len(state.registry.Keys))
	}
	if state.loggedIn {
		t.Error("expected loggedIn = false initially")
	}
	if state.offline {
		t.Error("expected offline = false initially")
	}
	if state.githubUser != "" {
		t.Errorf("expected empty githubUser initially, got %q", state.githubUser)
	}
	if state.githubToken.AccessToken != "" {
		t.Error("expected empty githubToken initially")
	}
}

func TestAppState_InitialGitHubState(t *testing.T) {
	state := &appState{}
	if state.loggedIn {
		t.Error("loggedIn should default to false")
	}
	if state.offline {
		t.Error("offline should default to false")
	}
	if state.githubUser != "" {
		t.Errorf("githubUser should default to empty, got %q", state.githubUser)
	}
	if state.githubToken != (ghapi.Token{}) {
		t.Error("githubToken should default to zero value")
	}
}

func TestTableColumns(t *testing.T) {
	if len(tableColumns) != len(tableColumnWidths) {
		t.Errorf("tableColumns (%d) and tableColumnWidths (%d) length mismatch",
			len(tableColumns), len(tableColumnWidths))
	}
	expected := []string{"#", "Authority", "From", "To", "Restrictions", "Note", "Fingerprint"}
	for i, col := range expected {
		if tableColumns[i] != col {
			t.Errorf("tableColumns[%d] = %q, want %q", i, tableColumns[i], col)
		}
	}
}

func TestIsDirty_InitiallyFalse(t *testing.T) {
	state := &appState{selected: -1}
	rt := &RegistryTab{state: state}
	if rt.IsDirty() {
		t.Error("expected IsDirty() = false initially")
	}
}

func TestIsDirty_AfterMutation(t *testing.T) {
	state := &appState{selected: -1, dirty: true}
	rt := &RegistryTab{state: state}
	if !rt.IsDirty() {
		t.Error("expected IsDirty() = true after mutation")
	}
}

func TestAppState_NotLoggedIn_Preconditions(t *testing.T) {
	state := &appState{loggedIn: false}
	if state.loggedIn {
		t.Error("state should not be loggedIn")
	}
}

func TestAppState_LoggedInOnline_Preconditions(t *testing.T) {
	state := &appState{loggedIn: true, offline: false, githubUser: "testuser"}
	if !state.loggedIn {
		t.Error("state should be loggedIn")
	}
	if state.offline {
		t.Error("state should not be offline")
	}
	if state.githubUser != "testuser" {
		t.Errorf("expected githubUser = testuser, got %q", state.githubUser)
	}
}

func TestAppState_LoggedInOffline_Preconditions(t *testing.T) {
	state := &appState{loggedIn: true, offline: true, githubUser: ""}
	if !state.loggedIn {
		t.Error("state should be loggedIn")
	}
	if !state.offline {
		t.Error("state should be offline")
	}
}

func TestAppState_SubmitPreconditions_NotLoggedIn(t *testing.T) {
	state := &appState{
		registry: core.Registry{Keys: []core.KeyEntry{{Authority: "A"}}},
		loggedIn: false,
	}
	rt := &RegistryTab{state: state}
	// Verify the preconditions: service.CanSave is true but not logged in.
	if !service.CanSave(rt.state.registry) {
		t.Error("CanSave should return true for non-empty registry")
	}
	if rt.state.loggedIn {
		t.Error("should not be logged in")
	}
}

func TestSubmitting_AtomicGuard(t *testing.T) {
	rt := &RegistryTab{state: &appState{}}
	// First swap should succeed.
	if !rt.submitting.CompareAndSwap(false, true) {
		t.Error("first CompareAndSwap should succeed")
	}
	// Second swap should fail (already submitting).
	if rt.submitting.CompareAndSwap(false, true) {
		t.Error("second CompareAndSwap should fail while submitting")
	}
	// Reset.
	rt.submitting.Store(false)
	if !rt.submitting.CompareAndSwap(false, true) {
		t.Error("CompareAndSwap should succeed after reset")
	}
}

func TestRegistryTab_FieldsExist(t *testing.T) {
	// Verify that RegistryTab has all expected fields with correct types.
	kr := ghapi.NewFakeKeyring()
	state := &appState{selected: -1}
	rt := &RegistryTab{
		state:     state,
		configDir: "/tmp/test",
		kr:        kr,
	}
	if rt.configDir != "/tmp/test" {
		t.Errorf("configDir = %q, want /tmp/test", rt.configDir)
	}
	if rt.kr == nil {
		t.Error("kr should not be nil")
	}
}

// --- VerificationURI host allowlist tests ---
// These test the URL validation logic used in showLoginDialog.

func TestVerificationURI_ValidGitHub(t *testing.T) {
	uri := "https://github.com/login/device"
	parsedURL, err := url.Parse(uri)
	if err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com" {
		t.Error("valid GitHub URI should pass all checks")
	}
}

func TestVerificationURI_WrongHost(t *testing.T) {
	uri := "https://evil.com/login/device"
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("wrong host should be rejected")
	}
}

func TestVerificationURI_HTTPScheme(t *testing.T) {
	uri := "http://github.com/login/device"
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("http scheme should be rejected")
	}
}

func TestVerificationURI_SubdomainNotAllowed(t *testing.T) {
	uri := "https://evil.github.com/login/device"
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("subdomain of github.com should be rejected")
	}
}

func TestVerificationURI_EmptyString(t *testing.T) {
	uri := ""
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("empty URI should be rejected")
	}
}

func TestVerificationURI_JavaScriptScheme(t *testing.T) {
	uri := "javascript:alert(1)"
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("javascript: scheme should be rejected")
	}
}

func TestVerificationURI_GitHubWithPort(t *testing.T) {
	uri := "https://github.com:8443/login/device"
	parsedURL, err := url.Parse(uri)
	invalid := err != nil || parsedURL == nil || parsedURL.Scheme != "https" || parsedURL.Host != "github.com"
	if !invalid {
		t.Error("github.com with non-standard port should be rejected")
	}
}

func TestEntryCellText_InvalidColumn(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	for _, col := range []int{-1, len(tableColumns), 100} {
		got := service.EntryCellText(entry, col, 0, nil)
		if got != "" {
			t.Errorf("col %d: got %q, want empty string", col, got)
		}
	}
}

// --- GitHubClient tests ---

func TestGitHubClient_NotLoggedIn(t *testing.T) {
	rt := &RegistryTab{state: &appState{loggedIn: false}}
	if rt.GitHubClient() != nil {
		t.Error("expected nil when not logged in")
	}
}

func TestGitHubClient_EmptyAccessToken(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "testuser",
		githubToken: ghapi.Token{AccessToken: ""},
	}}
	if rt.GitHubClient() != nil {
		t.Error("expected nil when AccessToken is empty")
	}
}

func TestGitHubClient_Offline(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		offline:     true,
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	if rt.GitHubClient() != nil {
		t.Error("expected nil when offline")
	}
}

// The display name is not needed to build a client: PRs are same-repo.
func TestGitHubClient_EmptyUsername(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "",
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	if rt.GitHubClient() == nil {
		t.Error("expected a client when githubUser is empty")
	}
}

func TestGitHubClient_AllConditionsMet(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "testuser",
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	client := rt.GitHubClient()
	if client == nil {
		t.Fatal("expected non-nil client when all conditions met")
	}
	if client.Owner != ghapi.DefaultOwner {
		t.Errorf("Owner = %q, want %q", client.Owner, ghapi.DefaultOwner)
	}
	if client.Repo != ghapi.DefaultRepo {
		t.Errorf("Repo = %q, want %q", client.Repo, ghapi.DefaultRepo)
	}
}

// --- onLoginChanged observer tests ---

// TestUpdateLoginUI_FiresObserver verifies the login-state choke point invokes a
// registered observer, so other tabs (History) react to auth changes.
func TestUpdateLoginUI_FiresObserver(t *testing.T) {
	rt := newTestRegistryTab(t)
	fired := 0
	rt.SetOnLoginChanged(func() { fired++ })

	rt.updateLoginUI()

	if fired != 1 {
		t.Fatalf("onLoginChanged fired %d times, want 1", fired)
	}
}

// TestUpdateLoginUI_NilObserverNoPanic verifies updateLoginUI is safe when no
// observer is registered (the test / early-construction case) and still runs its
// primary work (setting the login button text for the logged-out state).
func TestUpdateLoginUI_NilObserverNoPanic(t *testing.T) {
	rt := newTestRegistryTab(t)
	// Seed a distinct value so the post-call assertion can only pass if
	// updateLoginUI genuinely rewrote the button text.
	rt.loginBtn.SetText("stale")
	// onLoginChanged is nil (never set) — must not panic.
	rt.updateLoginUI()
	if rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("loginBtn.Text = %q, want %q (method must run its work path)",
			rt.loginBtn.Text, "Login to GitHub")
	}
}

// TestCompleteLogin_FiresObserver locks the load-bearing invariant that the
// login-state transitions route through updateLoginUI (and therefore fire the
// observer). Testing updateLoginUI directly is not enough: a future transition
// that mutates login state without calling updateLoginUI would leave the History
// tab stale. Driving the real completeLogin path pins that guarantee for the
// online, offline, and unauthorized outcomes.
func TestCompleteLogin_FiresObserver(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		valErr       error
		wantLoggedIn bool
		wantOffline  bool
		wantToken    string // expected persisted AccessToken ("" = cleared)
	}{
		{"online", "octocat", nil, true, false, "tok-123"},
		{"offline (non-401 error)", "octocat", errors.New("network unreachable"), true, true, "tok-123"},
		{"unauthorized (401)", "", &ghapi.APIError{StatusCode: 401, Message: "bad credentials"}, false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := newTestRegistryTab(t)
			fired := 0
			rt.SetOnLoginChanged(func() { fired++ })

			rt.completeLogin(ghapi.Token{AccessToken: "tok-123"}, tt.username, tt.valErr, func() {})

			if fired != 1 {
				t.Errorf("onLoginChanged fired %d times, want 1", fired)
			}
			if rt.state.loggedIn != tt.wantLoggedIn {
				t.Errorf("loggedIn = %v, want %v", rt.state.loggedIn, tt.wantLoggedIn)
			}
			if rt.state.offline != tt.wantOffline {
				t.Errorf("offline = %v, want %v", rt.state.offline, tt.wantOffline)
			}
			if rt.state.githubToken.AccessToken != tt.wantToken {
				t.Errorf("githubToken.AccessToken = %q, want %q (persist/clear invariant)",
					rt.state.githubToken.AccessToken, tt.wantToken)
			}
		})
	}
}

// Verify widget.Button type is accessible (compile-time check for RegistryTab.loginBtn field).
var _ *widget.Button
