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

// Login runs the GitHub device authorization flow, emitting
// EventAuthDeviceCode once the user has a code to enter. A Login stopped by
// CancelLogin, Close or ctx returns an error matching ctx.Err().
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
func (a *App) restore(ctx context.Context) AuthState {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tok, username, loggedIn, offline, err := a.restoreSession(ctx, a.keyring, a.dataDir)
	if err != nil {
		a.logger.Logf("warning: token restore failed: %s", core.SanitizeForLog(err.Error()))
	}
	return a.setAuth(tok, username, loggedIn, offline)
}

// Reconnect retries restoring the saved session (after GitHub was
// unreachable) and returns the applied state; a restore failure is logged and
// leaves the state logged out. It returns ErrBusy while a Login runs.
func (a *App) Reconnect(ctx context.Context) (AuthState, error) {
	if !a.loggingIn.CompareAndSwap(false, true) {
		return AuthState{}, ErrBusy
	}
	defer a.loggingIn.Store(false)
	return a.restore(ctx), nil
}

// startupRestore silently restores the saved session (with a keyring), then
// loads the registry for editing. Start runs it.
func (a *App) startupRestore() {
	if a.keyring != nil {
		a.restore(context.Background())
	}
	a.mu.Lock()
	loaded := a.baseBytes != nil
	a.mu.Unlock()
	if loaded { // a Fetch from Server finished during the restore; keep its edits
		return
	}
	if err := a.FetchRegistry(context.Background()); err != nil {
		a.events.Emit(EventRegistryChanged, nil)
	}
}

// Logout clears the saved token and logs out. Hosts also call it after a
// GitHub 401: an expired session means logged out, not offline.
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

// GitHubClient returns a client for the logged-in session, or nil when logged
// out or offline.
func (a *App) GitHubClient() *ghapi.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clientLocked()
}
