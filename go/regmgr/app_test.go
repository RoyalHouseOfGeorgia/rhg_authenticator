package regmgr

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"

	"fyne.io/fyne/v2/widget"
)

func TestCanSave_EmptyRegistry(t *testing.T) {
	reg := core.Registry{Keys: nil}
	if canSave(reg) {
		t.Error("canSave should return false for empty registry")
	}
}

func TestCanSave_EmptySlice(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{}}
	if canSave(reg) {
		t.Error("canSave should return false for zero-length Keys slice")
	}
}

func TestCanSave_NonEmpty(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{{Authority: "A"}}}
	if !canSave(reg) {
		t.Error("canSave should return true for non-empty registry")
	}
}

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
	// Verify the preconditions: canSave is true but not logged in.
	if !canSave(rt.state.registry) {
		t.Error("canSave should return true for non-empty registry")
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

// --- resolveLoginState tests ---

func TestResolveLoginState_Online(t *testing.T) {
	loggedIn, offline, text := resolveLoginState(false, "myuser", false)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Logged in as @myuser" {
		t.Errorf("statusText = %q, want %q", text, "Logged in as @myuser")
	}
}

func TestResolveLoginState_Unauthorized(t *testing.T) {
	loggedIn, offline, text := resolveLoginState(true, "", true)
	if loggedIn {
		t.Error("loggedIn = true, want false")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Not logged in" {
		t.Errorf("statusText = %q, want %q", text, "Not logged in")
	}
}

func TestResolveLoginState_Offline(t *testing.T) {
	loggedIn, offline, text := resolveLoginState(false, "", true)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if !offline {
		t.Error("offline = false, want true")
	}
	if text != "GitHub unreachable" {
		t.Errorf("statusText = %q, want %q", text, "GitHub unreachable")
	}
}

func TestResolveLoginState_EmptyUsername(t *testing.T) {
	// No error but empty username — still logged in, just no name to display.
	loggedIn, offline, text := resolveLoginState(false, "", false)
	if !loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if offline {
		t.Error("offline = true, want false")
	}
	if text != "Logged in as @" {
		t.Errorf("statusText = %q, want %q", text, "Logged in as @")
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

// --- entryCellText tests ---

func TestEntryCellText_Column0_RowNumber(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        nil,
		Algorithm: "Ed25519",
		PublicKey: "dGVzdA==",
		Note:      "test note",
	}
	got := entryCellText(entry, 0, 0, nil)
	if got != "1" {
		t.Errorf("col 0: got %q, want %q", got, "1")
	}
	// Also verify with a different index.
	got = entryCellText(entry, 0, 4, nil)
	if got != "5" {
		t.Errorf("col 0 idx 4: got %q, want %q", got, "5")
	}
}

func TestEntryCellText_Column1_Authority(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 1, 0, nil)
	if got != "Test Auth" {
		t.Errorf("col 1: got %q, want %q", got, "Test Auth")
	}
}

func TestEntryCellText_Column2_From(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 2, 0, nil)
	want := core.FormatDateDisplay("2026-01-15")
	if got != want {
		t.Errorf("col 2: got %q, want %q", got, want)
	}
}

func TestEntryCellText_Column3_ToNil(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        nil,
		Note:      "test note",
	}
	got := entryCellText(entry, 3, 0, nil)
	if got != "(none)" {
		t.Errorf("col 3 nil To: got %q, want %q", got, "(none)")
	}
}

func TestEntryCellText_Column3_ToNonNil(t *testing.T) {
	toDate := "2027-06-30"
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		To:        &toDate,
		Note:      "test note",
	}
	got := entryCellText(entry, 3, 0, nil)
	want := core.FormatDateDisplay("2027-06-30")
	if got != want {
		t.Errorf("col 3 non-nil To: got %q, want %q", got, want)
	}
}

func TestEntryCellText_Column4_Restrictions(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Extra:     map[string]json.RawMessage{"allowed_honors": json.RawMessage(`["Appointment"]`)},
	}
	got := entryCellText(entry, 4, 0, nil)
	if got != "Appointment" {
		t.Errorf("col 4: got %q, want %q", got, "Appointment")
	}
}

func TestEntryCellText_Column5_Note(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 5, 0, nil)
	if got != "test note" {
		t.Errorf("col 5: got %q, want %q", got, "test note")
	}
}

func TestEntryCellText_Column6_CacheHit(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	cache := map[int]string{0: "SHA256:abc123"}
	got := entryCellText(entry, 6, 0, cache)
	if got != "SHA256:abc123" {
		t.Errorf("col 6 cache hit: got %q, want %q", got, "SHA256:abc123")
	}
}

func TestEntryCellText_Column6_CacheMiss(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	cache := map[int]string{99: "SHA256:other"}
	got := entryCellText(entry, 6, 0, cache)
	if got != "(invalid key)" {
		t.Errorf("col 6 cache miss: got %q, want %q", got, "(invalid key)")
	}
}

func TestEntryCellText_Column6_NilCache(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 6, 0, nil)
	if got != "(invalid key)" {
		t.Errorf("col 6 nil cache: got %q, want %q", got, "(invalid key)")
	}
}

func TestRestrictionsText(t *testing.T) {
	tests := []struct {
		name string
		raw  string // "" means allowed_honors absent from Extra
		want string
	}{
		{"absent", "", "(none)"},
		{"null", `null`, "(none)"},
		{"empty array", `[]`, "(none)"},
		{"all blank", `["", "  "]`, "(none)"},
		{"single honor", `["Appointment"]`, "Appointment"},
		{"blank items skipped", `["A", "", "B"]`, "A, B"},
		{"non-array string", `"Appointment"`, "(invalid)"},
		{"non-array object", `{"a": 1}`, "(invalid)"},
		{"malformed json", `[`, "(invalid)"},
		{"non-string item", `[1]`, "(invalid)"},
		{"null item", `["A", null]`, "(invalid)"},
		{"leading whitespace", `[" A"]`, "(invalid)"},
		{"trailing whitespace", `["A "]`, "(invalid)"},
		{"bidi control char", `["A\u202e"]`, "(invalid)"},
		{"C0 control char", `["A\u0001B"]`, "(invalid)"},
		{"tab only is control not blank", `["\t"]`, "(invalid)"},
		// U+FEFF: JS trim() strips it, so the verify page treats these as blank / untrimmed.
		{"BOM only is blank like JS trim", `["\ufeff"]`, "(none)"},
		{"trailing BOM is untrimmed like JS trim", `["Medal\ufeff"]`, "(invalid)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := core.KeyEntry{Authority: "Test Auth", From: "2026-01-15"}
			if tt.raw != "" {
				entry.Extra = map[string]json.RawMessage{"allowed_honors": json.RawMessage(tt.raw)}
			}
			if got := restrictionsText(entry); got != tt.want {
				t.Errorf("restrictionsText(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestEntryCellText_InvalidColumn(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	for _, col := range []int{-1, len(tableColumns), 100} {
		got := entryCellText(entry, col, 0, nil)
		if got != "" {
			t.Errorf("col %d: got %q, want empty string", col, got)
		}
	}
}

// --- ClientForHistory tests ---

func TestClientForHistory_NotLoggedIn(t *testing.T) {
	rt := &RegistryTab{state: &appState{loggedIn: false}}
	if rt.ClientForHistory() != nil {
		t.Error("expected nil when not logged in")
	}
}

func TestClientForHistory_EmptyAccessToken(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "testuser",
		githubToken: ghapi.Token{AccessToken: ""},
	}}
	if rt.ClientForHistory() != nil {
		t.Error("expected nil when AccessToken is empty")
	}
}

func TestClientForHistory_Offline(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		offline:     true,
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	if rt.ClientForHistory() != nil {
		t.Error("expected nil when offline")
	}
}

// The display name is not needed to build a client: PRs are same-repo.
func TestClientForHistory_EmptyUsername(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "",
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	if rt.ClientForHistory() == nil {
		t.Error("expected a client when githubUser is empty")
	}
}

func TestClientForHistory_AllConditionsMet(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:    true,
		githubUser:  "testuser",
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	client := rt.ClientForHistory()
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

// --- isSafeGitHubURL tests ---

func TestIsSafeGitHubURL_GitHubHTTPS(t *testing.T) {
	_, ok := isSafeGitHubURL("https://github.com/org/repo/pull/1")
	if !ok {
		t.Error("expected true for https://github.com URL")
	}
}

func TestIsSafeGitHubURL_GitHubSubdomain(t *testing.T) {
	_, ok := isSafeGitHubURL("https://gist.github.com/user/123")
	if !ok {
		t.Error("expected true for https://gist.github.com URL")
	}
}

func TestIsSafeGitHubURL_NonGitHub(t *testing.T) {
	_, ok := isSafeGitHubURL("https://evil.com/phishing")
	if ok {
		t.Error("expected false for non-GitHub host")
	}
}

func TestIsSafeGitHubURL_HTTP(t *testing.T) {
	_, ok := isSafeGitHubURL("http://github.com/org/repo/pull/1")
	if ok {
		t.Error("expected false for http scheme")
	}
}

func TestIsSafeGitHubURL_Empty(t *testing.T) {
	_, ok := isSafeGitHubURL("")
	if ok {
		t.Error("expected false for empty URL")
	}
}

func TestIsSafeGitHubURL_SuffixConfusion(t *testing.T) {
	_, ok := isSafeGitHubURL("https://evil-github.com/fake")
	if ok {
		t.Error("expected false for evil-github.com (suffix confusion)")
	}
}

// Verify widget.Button type is accessible (compile-time check for RegistryTab.loginBtn field).
var _ *widget.Button
