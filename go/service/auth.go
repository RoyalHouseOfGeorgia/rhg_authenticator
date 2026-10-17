package service

import (
	"context"
	"fmt"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

// AuthState is the GitHub login state.
type AuthState struct {
	LoggedIn, Offline bool
	User              string
}

// DeviceCode is the EventAuthDeviceCode payload. VerificationURI is "" unless
// it is an https URL on github.com.
type DeviceCode struct{ UserCode, VerificationURI string }

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
// matching ctx.Err(); the login state is unchanged, except that a restore
// that already finished (and ended logged out) stays applied when the device
// flow that followed it is cancelled.
func (a *App) Login(ctx context.Context) (AuthState, error) {
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
		return AuthState{}, fmt.Errorf("device code request failed: %w", err)
	}
	uri := dcr.VerificationURI
	if ghapi.ParseGitHubURL(uri) == nil {
		a.logger.Logf("warning: invalid verification URI: %s", core.SanitizeForLog(uri))
		uri = ""
	}
	a.events.Emit(EventAuthDeviceCode, DeviceCode{UserCode: dcr.UserCode, VerificationURI: uri})

	tok, err := a.pollForToken(ctx, dcr.DeviceCode, dcr.Interval, dcr.ExpiresIn)
	if err != nil {
		return AuthState{}, fmt.Errorf("login failed: %w", err)
	}

	// Validate the token to get the username before persisting.
	valCtx, valCancel := context.WithTimeout(ctx, 10*time.Second)
	defer valCancel()
	username, valErr := a.validateToken(valCtx, tok)
	if err := ctx.Err(); err != nil { // cancelled while validating: keep no token
		return AuthState{}, err
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
		return AuthState{}, cerr
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
	if loaded { // a Fetch from Server finished during the restore; keep its edits
		return
	}
	if err := a.loadEditRegistry(context.Background(), true); err != nil {
		a.events.Emit(EventRegistryChanged, nil)
	}
}

// Logout clears the saved token and logs out. Revoke and SubmitRegistry call
// it themselves after a GitHub 401 (an expired session means logged out, not
// offline), so hosts never need to.
func (a *App) Logout() {
	if err := ghapi.ClearToken(a.keyring, a.dataDir); err != nil {
		a.logger.Logf("warning: clearing token failed: %s", core.SanitizeForLog(err.Error()))
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
