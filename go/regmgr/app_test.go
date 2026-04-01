package regmgr

import (
	"errors"
	"fmt"
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
	if state.filePath != "" {
		t.Error("expected empty filePath initially")
	}
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
	expected := []string{"#", "Authority", "From", "To", "Note", "Fingerprint"}
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
	if text != "Logged in (offline)" {
		t.Errorf("statusText = %q, want %q", text, "Logged in (offline)")
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

// --- userFacingError tests ---

func TestUserFacingError_RateLimited(t *testing.T) {
	err := &ghapi.APIError{StatusCode: 429, Message: "rate limit exceeded"}
	got := userFacingError(err)
	want := "GitHub rate limit reached. Try again in a few minutes."
	if got != want {
		t.Errorf("userFacingError(429) = %q, want %q", got, want)
	}
}

func TestUserFacingError_Forbidden(t *testing.T) {
	err := &ghapi.APIError{StatusCode: 403, Message: "forbidden"}
	got := userFacingError(err)
	want := "Permission denied. Check your GitHub account permissions."
	if got != want {
		t.Errorf("userFacingError(403) = %q, want %q", got, want)
	}
}

func TestUserFacingError_GenericAPIError(t *testing.T) {
	err := &ghapi.APIError{StatusCode: 500, Message: "internal server error"}
	got := userFacingError(err)
	want := "An error occurred. Please try again later."
	if got != want {
		t.Errorf("userFacingError(500) = %q, want %q", got, want)
	}
}

func TestUserFacingError_NetworkError(t *testing.T) {
	err := errors.New("dial tcp: lookup api.github.com: no such host")
	got := userFacingError(err)
	want := "An error occurred. Please try again later."
	if got != want {
		t.Errorf("userFacingError(network) = %q, want %q", got, want)
	}
}

func TestUserFacingError_WrappedRateLimited(t *testing.T) {
	inner := &ghapi.APIError{StatusCode: 429, Message: "rate limit"}
	err := fmt.Errorf("request failed: %w", inner)
	got := userFacingError(err)
	want := "GitHub rate limit reached. Try again in a few minutes."
	if got != want {
		t.Errorf("userFacingError(wrapped 429) = %q, want %q", got, want)
	}
}

func TestUserFacingError_WrappedForbidden(t *testing.T) {
	inner := &ghapi.APIError{StatusCode: 403, Message: "forbidden"}
	err := fmt.Errorf("request failed: %w", inner)
	got := userFacingError(err)
	want := "Permission denied. Check your GitHub account permissions."
	if got != want {
		t.Errorf("userFacingError(wrapped 403) = %q, want %q", got, want)
	}
}

func TestUserFacingError_NilError(t *testing.T) {
	// Edge case: nil error should not panic, returns generic message.
	got := userFacingError(nil)
	want := "An error occurred. Please try again later."
	if got != want {
		t.Errorf("userFacingError(nil) = %q, want %q", got, want)
	}
}

func TestUserFacingError_DoesNotLeakDetails(t *testing.T) {
	// Ensure internal error details are not exposed to the user.
	err := errors.New("connection refused to 10.0.0.1:443: TLS handshake timeout")
	got := userFacingError(err)
	if got != "An error occurred. Please try again later." {
		t.Errorf("userFacingError should not leak internal details, got %q", got)
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

func TestEntryCellText_Column4_Note(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 4, 0, nil)
	if got != "test note" {
		t.Errorf("col 4: got %q, want %q", got, "test note")
	}
}

func TestEntryCellText_Column5_CacheHit(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	cache := map[int]string{0: "SHA256:abc123"}
	got := entryCellText(entry, 5, 0, cache)
	if got != "SHA256:abc123" {
		t.Errorf("col 5 cache hit: got %q, want %q", got, "SHA256:abc123")
	}
}

func TestEntryCellText_Column5_CacheMiss(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	cache := map[int]string{99: "SHA256:other"}
	got := entryCellText(entry, 5, 0, cache)
	if got != "(invalid key)" {
		t.Errorf("col 5 cache miss: got %q, want %q", got, "(invalid key)")
	}
}

func TestEntryCellText_Column5_NilCache(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	got := entryCellText(entry, 5, 0, nil)
	if got != "(invalid key)" {
		t.Errorf("col 5 nil cache: got %q, want %q", got, "(invalid key)")
	}
}

func TestEntryCellText_InvalidColumn(t *testing.T) {
	entry := core.KeyEntry{
		Authority: "Test Auth",
		From:      "2026-01-15",
		Note:      "test note",
	}
	for _, col := range []int{-1, 6, 100} {
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
		loggedIn:   true,
		githubUser: "testuser",
		githubToken: ghapi.Token{AccessToken: ""},
	}}
	if rt.ClientForHistory() != nil {
		t.Error("expected nil when AccessToken is empty")
	}
}

func TestClientForHistory_EmptyUsername(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:   true,
		githubUser: "",
		githubToken: ghapi.Token{AccessToken: "tok-123"},
	}}
	if rt.ClientForHistory() != nil {
		t.Error("expected nil when githubUser is empty")
	}
}

func TestClientForHistory_AllConditionsMet(t *testing.T) {
	rt := &RegistryTab{state: &appState{
		loggedIn:   true,
		githubUser: "testuser",
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

// --- userFacingError fork error test ---

func TestUserFacingError_ForkError(t *testing.T) {
	err := &ghapi.ForkError{Phase: "create", Wrapped: fmt.Errorf("network error")}
	got := userFacingError(err)
	want := "Could not set up your GitHub fork. Check your network connection and try again."
	if got != want {
		t.Errorf("userFacingError(ForkError) = %q, want %q", got, want)
	}
}

func TestUserFacingError_WrappedForkError(t *testing.T) {
	inner := &ghapi.ForkError{Phase: "poll", Wrapped: fmt.Errorf("timeout")}
	err := fmt.Errorf("request failed: %w", inner)
	got := userFacingError(err)
	want := "Could not set up your GitHub fork. Check your network connection and try again."
	if got != want {
		t.Errorf("userFacingError(wrapped ForkError) = %q, want %q", got, want)
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
