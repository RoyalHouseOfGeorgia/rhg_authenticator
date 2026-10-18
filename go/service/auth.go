package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// ErrLoginUnavailable is returned by Login when the App has no Keyring: GitHub
// login can't work on this computer, so a UI need not offer it again.
var ErrLoginUnavailable = errors.New("GitHub login isn't available: no secure credential store on this computer.")

// AuthState is the GitHub login state.
type AuthState struct {
	LoggedIn bool   `json:"loggedIn"`
	Offline  bool   `json:"offline"`
	User     string `json:"user"`
}

// DeviceCode is the EventAuthDeviceCode payload. VerificationURI is "" unless
// it is an https URL on github.com.
type DeviceCode struct {
	UserCode        string `json:"userCode"`
	VerificationURI string `json:"verificationUri"`
}

// StatusText is the status-line text for s.
func (s AuthState) StatusText() string {
	switch {
	case !s.LoggedIn:
		return "Not logged in"
	case s.Offline:
		return "GitHub unreachable"
	default:
		return "Logged in as @" + s.User
	}
}

// MarshalJSON encodes s with its StatusText as "statusText", so a JSON client
// shows the same status line.
func (s AuthState) MarshalJSON() ([]byte, error) {
	type fields AuthState // drops this method, so Marshal doesn't recurse
	return json.Marshal(struct {
		fields
		StatusText string `json:"statusText"`
	}{fields(s), s.StatusText()})
}

// setAuth applies a login state and emits EventAuthChanged.
func (a *App) setAuth(tok ghapi.Token, user string, loggedIn, offline bool) AuthState {
	a.mu.Lock()
	a.token, a.githubUser, a.loggedIn, a.offline = tok, user, loggedIn, offline
	st := a.authStateLocked()
	a.mu.Unlock()
	a.events.Emit(EventAuthChanged, st)
	return st
}

func (a *App) authStateLocked() AuthState {
	return AuthState{LoggedIn: a.loggedIn, Offline: a.offline, User: a.githubUser}
}

// AuthState returns the current GitHub login state.
func (a *App) AuthState() AuthState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authStateLocked()
}

// Login connects to GitHub: logged in and online it returns the current
// state; logged in but offline it retries restoring the saved session and
// returns the result unless that ends logged out. Logged out, it runs the
// device authorization flow, emitting EventAuthDeviceCode once the user has a
// code to enter. A Login stopped by CancelLogin, Close or ctx returns an error
// wrapping ctx.Err() (matching context.Canceled when cancelled); the login
// state is unchanged,
// except that a restore that already finished (and ended logged out) stays
// applied when the device flow that followed it is cancelled. It returns
// ErrBusy while another Login runs; a failed device flow returns an error
// with user-facing text that wraps the GitHub error. Without a Keyring it
// returns ErrLoginUnavailable and changes nothing.
func (a *App) Login(ctx context.Context) (AuthState, error) {
	if a.keyring == nil {
		return AuthState{}, ErrLoginUnavailable
	}
	if !a.loggingIn.CompareAndSwap(false, true) {
		return AuthState{}, ErrBusy
	}
	defer a.loggingIn.Store(false)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.mu.Lock()
	a.loginCancel = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.loginCancel = nil
		a.mu.Unlock()
	}()

	if st := a.AuthState(); st.LoggedIn {
		if !st.Offline {
			return st, nil
		}
		st, err := a.restore(ctx)
		if err != nil {
			return AuthState{}, err
		}
		if st.LoggedIn {
			return st, nil
		}
	}

	dcr, err := a.requestDeviceCode(ctx)
	if err != nil {
		return AuthState{}, a.loginError(ctx, "device code request", err)
	}
	uri := ghapi.GitHubURLOrEmpty(dcr.VerificationURI)
	if uri == "" {
		a.logger.Logf("warning: invalid verification URI: %s", core.SanitizeForLog(dcr.VerificationURI))
	}
	a.events.Emit(EventAuthDeviceCode, DeviceCode{UserCode: dcr.UserCode, VerificationURI: uri})

	tok, err := a.pollForToken(ctx, dcr.DeviceCode, dcr.Interval, dcr.ExpiresIn)
	if err != nil {
		return AuthState{}, a.loginError(ctx, "token polling", err)
	}

	// Validate the token to get the username before persisting.
	valCtx, valCancel := context.WithTimeout(ctx, 10*time.Second)
	defer valCancel()
	username, valErr := a.validateToken(valCtx, tok)
	if err := ctx.Err(); err != nil { // cancelled while validating: keep no token
		return AuthState{}, loginStopped(err)
	}
	if valErr != nil {
		a.logger.Logf("warning: token validation failed: %s", core.SanitizeForLog(valErr.Error()))
	}
	if ghapi.IsUnauthorized(valErr) {
		return a.setAuth(ghapi.Token{}, username, false, false), nil
	}
	if err := ghapi.SaveToken(a.keyring, a.dataDir, tok); err != nil {
		a.logger.Logf("warning: failed to save token: %s", core.SanitizeForLog(err.Error()))
	}
	return a.setAuth(tok, username, true, valErr != nil), nil
}

// loginError is the Login error for a failed device-flow step: loginStopped
// once the login was stopped, else err (logged) behind its user-facing text.
func (a *App) loginError(ctx context.Context, step string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return loginStopped(cerr)
	}
	a.logger.Logf("warning: login %s failed: %s", step, core.SanitizeForLog(err.Error()))
	return userErr(loginMessage(err), err)
}

// loginStopped is the Login error once ctx ended with cerr.
func loginStopped(cerr error) error {
	return userErr("Login cancelled.", cerr)
}

// loginMessage returns the user-facing text for a failed device-flow step.
func loginMessage(err error) string {
	switch {
	case errors.Is(err, ghapi.ErrDeviceCodeExpired):
		return "The login code expired. Start the login again to get a new one."
	case errors.Is(err, ghapi.ErrAccessDenied):
		return "GitHub access was denied, so you are not logged in."
	case errors.Is(err, ghapi.ErrMissingScope):
		return "GitHub didn't grant the public_repo permission the app needs. Log in again and approve it."
	default:
		return ghapi.UserMessage(err)
	}
}

// CancelLogin stops a running Login.
func (a *App) CancelLogin() {
	a.mu.Lock()
	cancel := a.loginCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// restore reloads and validates the saved session and applies the result.
// If ctx is cancelled meanwhile it applies nothing and returns ctx.Err();
// its own timeout expiring is applied as offline.
func (a *App) restore(ctx context.Context) (AuthState, error) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tok, username, loggedIn, offline, err := a.restoreSession(rctx, a.keyring, a.dataDir)
	if cerr := ctx.Err(); cerr != nil {
		return AuthState{}, loginStopped(cerr)
	}
	if err != nil {
		a.logger.Logf("warning: token restore failed: %s", core.SanitizeForLog(err.Error()))
	}
	return a.setAuth(tok, username, loggedIn, offline), nil
}

// startupRestore silently restores the saved session (with a keyring), then
// loads the registry for editing. Start runs it.
func (a *App) startupRestore() {
	if a.keyring != nil {
		_, _ = a.restore(context.Background())
	}
	a.mu.Lock()
	loaded := a.baseBytes != nil
	a.mu.Unlock()
	if loaded { // a FetchRegistry finished during the restore; keep its edits
		return
	}
	if err := a.loadEditRegistry(context.Background(), true); err != nil {
		a.events.Emit(EventRegistryChanged, nil)
	}
}

// Logout clears the saved token (with a Keyring) and logs out. Revoke and
// SubmitRegistry call it themselves after a GitHub 401 (an expired session
// means logged out, not offline), so hosts never need to.
func (a *App) Logout() {
	// Without a keyring Login refuses, so this App never saved a token.
	if a.keyring != nil {
		if err := ghapi.ClearToken(a.keyring, a.dataDir); err != nil {
			a.logger.Logf("warning: clearing token failed: %s", core.SanitizeForLog(err.Error()))
		}
	}
	a.setAuth(ghapi.Token{}, "", false, false)
}

// clientLocked returns a GitHub client when logged in and online, or nil.
func (a *App) clientLocked() *ghapi.Client {
	if !a.loggedIn || a.offline || a.token.AccessToken == "" {
		return nil
	}
	return a.newClient(a.token.AccessToken)
}

// githubClient returns a client for the logged-in session, or nil when logged
// out or offline.
func (a *App) githubClient() *ghapi.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clientLocked()
}
