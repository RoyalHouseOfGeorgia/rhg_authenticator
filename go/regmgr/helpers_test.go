package regmgr

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// newTestRegistryTab creates a minimal RegistryTab with a test window for
// helper method unit tests. It does not initialise the full UI — only the
// fields that the extracted helpers depend on.
func newTestRegistryTab(t *testing.T) *RegistryTab {
	t.Helper()
	app := test.NewApp()
	t.Cleanup(func() { app.Quit() })
	w := app.NewWindow("test")
	btn := widget.NewButton("Login to GitHub", nil)
	return &RegistryTab{
		state:       &appState{selected: -1},
		statusLabel: widget.NewLabel(""),
		loginBtn:    btn,
		window:      w,
		configDir:   t.TempDir(),
		kr:          ghapi.NewFakeKeyring(),
	}
}

// ---------------------------------------------------------------------------
// handleDeviceCodeError
// ---------------------------------------------------------------------------

func TestHandleDeviceCodeError_ActiveContext(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Requesting device code...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt.handleDeviceCodeError(ctx, errors.New("network timeout"))

	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
}

func TestHandleDeviceCodeError_CancelledContext(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Requesting device code...")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling the handler

	rt.handleDeviceCodeError(ctx, errors.New("context cancelled"))

	// Status should still be cleared even with cancelled context.
	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
}

// ---------------------------------------------------------------------------
// handlePollError
// ---------------------------------------------------------------------------

func TestHandlePollError_ActiveContext(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Waiting for GitHub authorization...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt.handlePollError(ctx, errors.New("expired_token"))

	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
}

func TestHandlePollError_CancelledContext(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Waiting for GitHub authorization...")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rt.handlePollError(ctx, errors.New("context cancelled"))

	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
}

// ---------------------------------------------------------------------------
// completeLogin
// ---------------------------------------------------------------------------

func TestCompleteLogin_SuccessfulOnline(t *testing.T) {
	rt := newTestRegistryTab(t)
	tok := ghapi.Token{AccessToken: "gho_test123", TokenType: "bearer", Scope: "public_repo"}
	cancelled := false
	cancel := func() { cancelled = true }

	rt.completeLogin(tok, "octocat", nil, cancel)

	if !rt.state.loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if rt.state.offline {
		t.Error("offline = true, want false")
	}
	if rt.state.githubUser != "octocat" {
		t.Errorf("githubUser = %q, want %q", rt.state.githubUser, "octocat")
	}
	if rt.state.githubToken.AccessToken != "gho_test123" {
		t.Errorf("githubToken.AccessToken = %q, want %q", rt.state.githubToken.AccessToken, "gho_test123")
	}
	if rt.statusLabel.Text != "Logged in as @octocat" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "Logged in as @octocat")
	}
	if rt.loginBtn.Text != "@octocat \u25BE" {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, "@octocat \u25BE")
	}
	if !cancelled {
		t.Error("cancel was not called")
	}
}

func TestCompleteLogin_Offline(t *testing.T) {
	rt := newTestRegistryTab(t)
	tok := ghapi.Token{AccessToken: "gho_test456", TokenType: "bearer", Scope: "public_repo"}
	cancelled := false
	cancel := func() { cancelled = true }
	netErr := errors.New("dial tcp: connection refused")

	rt.completeLogin(tok, "", netErr, cancel)

	if !rt.state.loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if !rt.state.offline {
		t.Error("offline = false, want true")
	}
	if rt.state.githubToken.AccessToken != "gho_test456" {
		t.Errorf("githubToken.AccessToken = %q, want %q", rt.state.githubToken.AccessToken, "gho_test456")
	}
	if rt.statusLabel.Text != "Logged in (offline)" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "Logged in (offline)")
	}
	if rt.loginBtn.Text != "Logged in (offline)" {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, "Logged in (offline)")
	}
	if !cancelled {
		t.Error("cancel was not called")
	}
}

func TestCompleteLogin_Unauthorized(t *testing.T) {
	rt := newTestRegistryTab(t)
	tok := ghapi.Token{AccessToken: "gho_revoked", TokenType: "bearer"}
	cancelled := false
	cancel := func() { cancelled = true }
	authErr := &ghapi.APIError{StatusCode: 401, Message: "Bad credentials"}

	rt.completeLogin(tok, "", authErr, cancel)

	if rt.state.loggedIn {
		t.Error("loggedIn = true, want false")
	}
	if rt.state.offline {
		t.Error("offline = true, want false")
	}
	if rt.state.githubToken.AccessToken != "" {
		t.Errorf("githubToken should be zero value, got AccessToken = %q", rt.state.githubToken.AccessToken)
	}
	if rt.statusLabel.Text != "Not logged in" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "Not logged in")
	}
	if rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, "Login to GitHub")
	}
	if !cancelled {
		t.Error("cancel was not called")
	}
}

func TestCompleteLogin_EmptyUsername(t *testing.T) {
	rt := newTestRegistryTab(t)
	tok := ghapi.Token{AccessToken: "gho_noname", TokenType: "bearer"}
	cancelled := false
	cancel := func() { cancelled = true }

	rt.completeLogin(tok, "", nil, cancel)

	if !rt.state.loggedIn {
		t.Error("loggedIn = false, want true")
	}
	if rt.state.offline {
		t.Error("offline = true, want false")
	}
	if rt.statusLabel.Text != "Logged in as @" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "Logged in as @")
	}
	if !cancelled {
		t.Error("cancel was not called")
	}
}

func TestCompleteLogin_DoesNotStoreTokenWhenUnauthorized(t *testing.T) {
	rt := newTestRegistryTab(t)
	// Pre-set a token to verify it gets cleared.
	rt.state.githubToken = ghapi.Token{AccessToken: "old_token"}
	rt.state.loggedIn = true
	authErr := &ghapi.APIError{StatusCode: 401, Message: "Bad credentials"}
	cancel := func() {}

	rt.completeLogin(ghapi.Token{AccessToken: "new_token"}, "", authErr, cancel)

	if rt.state.githubToken.AccessToken != "" {
		t.Errorf("token should be cleared on 401, got %q", rt.state.githubToken.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// handleSubmitError
// ---------------------------------------------------------------------------

func TestHandleSubmitError_Unauthorized(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.loggedIn = true
	rt.state.githubToken = ghapi.Token{AccessToken: "gho_expired"}
	rt.state.githubUser = "octocat"

	authErr := &ghapi.APIError{StatusCode: 401, Message: "Bad credentials"}

	rt.handleSubmitError(authErr)

	if rt.state.loggedIn {
		t.Error("loggedIn should be false after 401")
	}
	if rt.state.githubToken.AccessToken != "" {
		t.Error("githubToken should be cleared after 401")
	}
	if rt.state.githubUser != "" {
		t.Error("githubUser should be cleared after 401")
	}
	if rt.loginBtn.Text != "Login to GitHub" {
		t.Errorf("loginBtn.Text = %q, want %q", rt.loginBtn.Text, "Login to GitHub")
	}
	// Note: statusLabel is set to "Session expired..." but immediately overwritten
	// by startLogin() which sets "Requesting device code...", so we verify the
	// startLogin re-entry happened rather than checking the intermediate text.
	if rt.statusLabel.Text != "Requesting device code..." {
		t.Errorf("statusLabel = %q, want %q (startLogin should have been triggered)",
			rt.statusLabel.Text, "Requesting device code...")
	}
}

func TestHandleSubmitError_RateLimited(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Creating pull request...")

	rateLimitErr := &ghapi.APIError{StatusCode: 429, Message: "rate limit"}

	rt.handleSubmitError(rateLimitErr)

	// Should clear status on non-auth errors.
	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
	// State should be unchanged — still logged in if it was before.
}

func TestHandleSubmitError_Forbidden(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Creating pull request...")
	rt.state.loggedIn = true

	forbiddenErr := &ghapi.APIError{StatusCode: 403, Message: "forbidden"}

	rt.handleSubmitError(forbiddenErr)

	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
	// Should NOT clear auth state for 403.
	if !rt.state.loggedIn {
		t.Error("loggedIn should remain true for 403")
	}
}

func TestHandleSubmitError_GenericError(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.statusLabel.SetText("Creating pull request...")

	genericErr := errors.New("network timeout")

	rt.handleSubmitError(genericErr)

	if rt.statusLabel.Text != "" {
		t.Errorf("statusLabel = %q, want empty string", rt.statusLabel.Text)
	}
}

// ---------------------------------------------------------------------------
// handleSubmitSuccess
// ---------------------------------------------------------------------------

func TestHandleSubmitSuccess_ValidHTTPSURL(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.dirty = true

	pr := ghapi.PRResult{
		Number:  42,
		HTMLURL: "https://github.com/owner/repo/pull/42",
	}

	rt.handleSubmitSuccess(pr)

	if rt.state.dirty {
		t.Error("dirty should be false after successful submit")
	}
	if rt.statusLabel.Text != "PR #42 created" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "PR #42 created")
	}
}

func TestHandleSubmitSuccess_InvalidURL(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.dirty = true

	pr := ghapi.PRResult{
		Number:  99,
		HTMLURL: "http://insecure.example.com/pull/99", // not HTTPS
	}

	rt.handleSubmitSuccess(pr)

	if rt.state.dirty {
		t.Error("dirty should be false after successful submit")
	}
	if rt.statusLabel.Text != "PR #99 created" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "PR #99 created")
	}
}

func TestHandleSubmitSuccess_EmptyURL(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.dirty = true

	pr := ghapi.PRResult{
		Number:  7,
		HTMLURL: "",
	}

	rt.handleSubmitSuccess(pr)

	if rt.state.dirty {
		t.Error("dirty should be false after successful submit")
	}
	if rt.statusLabel.Text != "PR #7 created" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "PR #7 created")
	}
}

func TestHandleSubmitSuccess_MalformedURL(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.dirty = true

	pr := ghapi.PRResult{
		Number:  5,
		HTMLURL: "://bad-url",
	}

	rt.handleSubmitSuccess(pr)

	if rt.state.dirty {
		t.Error("dirty should be false after successful submit")
	}
	if rt.statusLabel.Text != "PR #5 created" {
		t.Errorf("statusLabel = %q, want %q", rt.statusLabel.Text, "PR #5 created")
	}
}

// ---------------------------------------------------------------------------
// Integration: verify helpers don't panic with zero-value state
// ---------------------------------------------------------------------------

func TestHandleDeviceCodeError_NilContextError(t *testing.T) {
	// Ensure handleDeviceCodeError doesn't panic with various error types.
	rt := newTestRegistryTab(t)
	ctx := context.Background()

	rt.handleDeviceCodeError(ctx, errors.New("simple error"))
	rt.handleDeviceCodeError(ctx, &ghapi.APIError{StatusCode: 500, Message: "server error"})
}

func TestHandlePollError_VariousErrors(t *testing.T) {
	rt := newTestRegistryTab(t)
	ctx := context.Background()

	rt.handlePollError(ctx, errors.New("expired_token"))
	rt.handlePollError(ctx, errors.New("access_denied"))
}

func TestHandleSubmitError_WrappedUnauthorized(t *testing.T) {
	rt := newTestRegistryTab(t)
	rt.state.loggedIn = true
	rt.state.githubToken = ghapi.Token{AccessToken: "gho_test"}
	rt.state.githubUser = "user"

	// Wrap the 401 error — IsUnauthorized uses errors.As, so wrapping should still match.
	inner := &ghapi.APIError{StatusCode: 401, Message: "Bad credentials"}
	wrappedErr := fmt.Errorf("submit failed: %w", inner)

	rt.handleSubmitError(wrappedErr)

	if rt.state.loggedIn {
		t.Error("loggedIn should be false after wrapped 401")
	}
	if rt.state.githubToken.AccessToken != "" {
		t.Error("githubToken should be cleared after wrapped 401")
	}
	if rt.state.githubUser != "" {
		t.Error("githubUser should be cleared after wrapped 401")
	}
}
