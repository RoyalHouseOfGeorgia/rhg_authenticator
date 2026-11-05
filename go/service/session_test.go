package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

var errNetwork = errors.New("dial tcp: no route to host")

// stubDeviceFlow replaces the GitHub device flow: the code request returns
// uri, the poll returns pollErr or a token, and validation returns user, valErr.
func stubDeviceFlow(a *App, uri string, pollErr error, user string, valErr error) {
	a.requestDeviceCode = func(context.Context) (ghapi.DeviceCodeResponse, error) {
		return ghapi.DeviceCodeResponse{DeviceCode: "dc", UserCode: "ABCD-1234", VerificationURI: uri, Interval: 5, ExpiresIn: 900}, nil
	}
	a.pollForToken = func(context.Context, string, int, int) (ghapi.Token, error) {
		if pollErr != nil {
			return ghapi.Token{}, pollErr
		}
		return ghapi.Token{AccessToken: "gho_new", CreatedAt: time.Now()}, nil
	}
	a.validateToken = func(context.Context, ghapi.Token) (string, error) {
		if valErr != nil {
			return "", valErr
		}
		return user, nil
	}
}

func stubRestore(a *App, tok ghapi.Token, user string, loggedIn, offline bool, err error) {
	a.restoreSession = func(context.Context, ghapi.Keyring, string) (ghapi.Token, string, bool, bool, error) {
		return tok, user, loggedIn, offline, err
	}
}

func eventNames(h *appHarness) []string {
	names, _ := h.events.snapshot()
	return names
}

func TestLogin_Outcomes(t *testing.T) {
	tests := []struct {
		name      string
		valErr    error
		want      AuthState
		wantSaved bool
	}{
		{"online", nil, AuthState{LoggedIn: true, User: "octocat"}, true},
		{"offline", errNetwork, AuthState{LoggedIn: true, Offline: true}, true},
		{"unauthorized", &ghapi.APIError{StatusCode: 401, Message: "bad"}, AuthState{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kr := ghapi.NewFakeKeyring()
			h := newAppHarness(t, kr)
			stubDeviceFlow(h.app, "https://github.com/login/device", nil, "octocat", tc.valErr)

			st, err := h.app.Login(context.Background())
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			if st != tc.want || h.app.AuthState() != tc.want {
				t.Errorf("state = %+v / %+v, want %+v", st, h.app.AuthState(), tc.want)
			}
			names, payloads := h.events.snapshot()
			if !reflect.DeepEqual(names, []string{EventAuthDeviceCode, EventAuthChanged}) {
				t.Fatalf("events = %v", names)
			}
			if dc := payloads[0].(DeviceCode); dc != (DeviceCode{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"}) {
				t.Errorf("DeviceCode = %+v", dc)
			}
			_, loadErr := ghapi.LoadToken(kr, h.dir)
			if saved := loadErr == nil; saved != tc.wantSaved {
				t.Errorf("token saved = %v, want %v", saved, tc.wantSaved)
			}
			if gotClient := h.app.githubClient() != nil; gotClient != (tc.want.LoggedIn && !tc.want.Offline) {
				t.Errorf("githubClient non-nil = %v", gotClient)
			}
			if tc.valErr != nil && !strings.Contains(h.debugLog(t), "warning: token validation failed") {
				t.Error("validation failure not logged")
			}
		})
	}
}

func TestLogin_InvalidVerificationURIBlanked(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	stubDeviceFlow(h.app, "https://evil.com/login/device", nil, "octocat", nil)
	if _, err := h.app.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	_, payloads := h.events.snapshot()
	if dc := payloads[0].(DeviceCode); dc.VerificationURI != "" || dc.UserCode != "ABCD-1234" {
		t.Errorf("DeviceCode = %+v, want blank URI", dc)
	}
	if !strings.Contains(h.debugLog(t), "warning: invalid verification URI: https://evil.com/login/device") {
		t.Error("invalid URI not logged")
	}
}

func TestLogin_SaveFailureLogged(t *testing.T) {
	kr := ghapi.NewFakeKeyring()
	h := newAppHarness(t, kr)
	stubDeviceFlow(h.app, "https://github.com/login/device", nil, "octocat", nil)
	kr.SimulateError = errors.New("keyring locked")
	// Linux's file fallback fails too: a path component is a regular file.
	blocker := filepath.Join(h.dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.app.dataDir = filepath.Join(blocker, "dir")

	if st, err := h.app.Login(context.Background()); err != nil || !st.LoggedIn {
		t.Fatalf("Login = %+v, %v", st, err)
	}
	if !strings.Contains(h.debugLog(t), "warning: failed to save token") {
		t.Error("save failure not logged")
	}
}

func TestLogin_Errors(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.app.requestDeviceCode = func(context.Context) (ghapi.DeviceCodeResponse, error) {
		return ghapi.DeviceCodeResponse{}, errNetwork
	}
	if _, err := h.app.Login(context.Background()); !errors.Is(err, errNetwork) || err.Error() != "An error occurred. Please try again later." {
		t.Errorf("err = %v, want ghapi.UserMessage's text wrapping the cause", err)
	}
	if !strings.Contains(h.debugLog(t), "warning: login device code request failed: "+errNetwork.Error()) {
		t.Error("device code failure not logged")
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}

	rateLimited := &ghapi.APIError{StatusCode: 429}
	stubDeviceFlow(h.app, "https://github.com/login/device", rateLimited, "", nil)
	_, err := h.app.Login(context.Background())
	var apiErr *ghapi.APIError
	if !errors.As(err, &apiErr) || err.Error() != "GitHub rate limit reached. Try again in a few minutes." {
		t.Errorf("err = %v, want ghapi.UserMessage's text wrapping the cause", err)
	}
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventAuthDeviceCode}) {
		t.Errorf("events = %v, want only the device code", names)
	}
	if h.app.AuthState() != (AuthState{}) {
		t.Errorf("state = %+v, want logged out", h.app.AuthState())
	}
}

// TestLogin_CancelReturnsContextError: once Login is cancelled, a failed
// device-flow step returns "Login cancelled." wrapping the ctx error, whatever
// the step returned.
func TestLogin_CancelReturnsContextError(t *testing.T) {
	t.Run("device code request", func(t *testing.T) {
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		h.app.requestDeviceCode = func(context.Context) (ghapi.DeviceCodeResponse, error) {
			h.app.CancelLogin()
			return ghapi.DeviceCodeResponse{}, errNetwork
		}
		if _, err := h.app.Login(context.Background()); !errors.Is(err, context.Canceled) || err.Error() != "Login cancelled." {
			t.Errorf("err = %v, want Login cancelled. wrapping context.Canceled", err)
		}
	})
	t.Run("token polling", func(t *testing.T) {
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		stubDeviceFlow(h.app, "https://github.com/login/device", nil, "", nil)
		h.app.pollForToken = func(context.Context, string, int, int) (ghapi.Token, error) {
			h.app.CancelLogin()
			return ghapi.Token{}, errors.New("poll aborted")
		}
		if _, err := h.app.Login(context.Background()); !errors.Is(err, context.Canceled) || err.Error() != "Login cancelled." {
			t.Errorf("err = %v, want Login cancelled. wrapping context.Canceled", err)
		}
		if h.app.AuthState() != (AuthState{}) {
			t.Errorf("state = %+v, want logged out", h.app.AuthState())
		}
	})
}

// blockingPoll makes pollForToken signal entered and wait for ctx.
func blockingPoll(a *App) chan struct{} {
	entered := make(chan struct{})
	a.pollForToken = func(ctx context.Context, _ string, _, _ int) (ghapi.Token, error) {
		close(entered)
		<-ctx.Done()
		return ghapi.Token{}, ctx.Err()
	}
	return entered
}

func TestLogin_BusyAndCancel(t *testing.T) {
	for name, stop := range map[string]func(*App){
		"CancelLogin": (*App).CancelLogin,
		"Close":       (*App).Close,
	} {
		t.Run(name, func(t *testing.T) {
			h := newAppHarness(t, ghapi.NewFakeKeyring())
			stubDeviceFlow(h.app, "https://github.com/login/device", nil, "", nil)
			entered := blockingPoll(h.app)
			done := make(chan error, 1)
			go func() {
				_, err := h.app.Login(context.Background())
				done <- err
			}()
			<-entered

			if _, err := h.app.Login(context.Background()); !errors.Is(err, ErrBusy) {
				t.Errorf("second Login err = %v, want ErrBusy", err)
			}
			stop(h.app)
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Login err = %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Login did not return after cancel")
			}
			h.app.CancelLogin() // no login running: no-op
		})
	}
}

func TestLogin_CancelWhileValidatingKeepsNoToken(t *testing.T) {
	kr := ghapi.NewFakeKeyring()
	h := newAppHarness(t, kr)
	stubDeviceFlow(h.app, "https://github.com/login/device", nil, "octocat", nil)
	h.app.validateToken = func(context.Context, ghapi.Token) (string, error) {
		h.app.CancelLogin() // the user presses Cancel after GitHub issued the token
		return "octocat", nil
	}
	if _, err := h.app.Login(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if h.app.AuthState().LoggedIn {
		t.Error("cancelled login ended logged in")
	}
	if _, err := ghapi.LoadToken(kr, h.dir); err == nil {
		t.Error("cancelled login saved the token")
	}
}

func TestEventAuthChanged_CarriesState(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.app.setAuth(ghapi.Token{AccessToken: "t"}, "octocat", true, false)
	_, payloads := h.events.snapshot()
	if len(payloads) != 1 || payloads[0] != (AuthState{LoggedIn: true, User: "octocat"}) {
		t.Errorf("payloads = %v, want the new AuthState", payloads)
	}
}

// noDeviceFlow makes the device code request fail the test.
func noDeviceFlow(t *testing.T, a *App) {
	a.requestDeviceCode = func(context.Context) (ghapi.DeviceCodeResponse, error) {
		t.Error("device flow started")
		return ghapi.DeviceCodeResponse{}, errNetwork
	}
}

// TestLogin_Policy covers what Login does for each starting state: online
// returns at once, offline retries the restore and falls through to the
// device flow only when that ends logged out.
func TestLogin_Policy(t *testing.T) {
	type restoreResult struct {
		user              string
		loggedIn, offline bool
		err               error
	}
	online := AuthState{LoggedIn: true, User: "octocat"}
	offline := AuthState{LoggedIn: true, Offline: true, User: "octocat"}
	tests := []struct {
		name       string
		start      AuthState
		restore    *restoreResult // nil: the restore must not run
		deviceFlow bool
		want       AuthState
		wantEvents []string
		wantLog    string
	}{
		{"already online", online, nil, false, online, nil, ""},
		{"offline, restore online", offline, &restoreResult{"someuser", true, false, nil}, false,
			AuthState{LoggedIn: true, User: "someuser"}, []string{EventAuthChanged}, ""},
		{"offline, restore still offline", offline, &restoreResult{"", true, true, nil}, false,
			AuthState{LoggedIn: true, Offline: true}, []string{EventAuthChanged}, ""},
		{"offline, restore logged out", offline, &restoreResult{"", false, false, errors.New("keyring broken")}, true,
			AuthState{LoggedIn: true, User: "newuser"}, []string{EventAuthChanged, EventAuthDeviceCode, EventAuthChanged},
			"warning: token restore failed: keyring broken"},
		{"logged out", AuthState{}, nil, true,
			AuthState{LoggedIn: true, User: "newuser"}, []string{EventAuthDeviceCode, EventAuthChanged}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, ghapi.NewFakeKeyring())
			if tc.start.LoggedIn {
				h.app.setAuth(ghapi.Token{AccessToken: "gho_old"}, tc.start.User, true, tc.start.Offline)
			}
			h.events.reset()
			if r := tc.restore; r != nil {
				stubRestore(h.app, ghapi.Token{AccessToken: "gho_restored"}, r.user, r.loggedIn, r.offline, r.err)
			} else {
				h.app.restoreSession = func(context.Context, ghapi.Keyring, string) (ghapi.Token, string, bool, bool, error) {
					t.Error("restore ran")
					return ghapi.Token{}, "", false, false, nil
				}
			}
			if tc.deviceFlow {
				stubDeviceFlow(h.app, "https://github.com/login/device", nil, "newuser", nil)
			} else {
				noDeviceFlow(t, h.app)
			}

			st, err := h.app.Login(context.Background())
			if err != nil || st != tc.want || h.app.AuthState() != tc.want {
				t.Errorf("Login = %+v, %v (state %+v), want %+v", st, err, h.app.AuthState(), tc.want)
			}
			if names := eventNames(h); !reflect.DeepEqual(names, tc.wantEvents) {
				t.Errorf("events = %v, want %v", names, tc.wantEvents)
			}
			if tc.wantLog != "" && !strings.Contains(h.debugLog(t), tc.wantLog) {
				t.Errorf("debug log missing %q", tc.wantLog)
			}
		})
	}
}

func TestLogin_CancelDuringRestoreAppliesNothing(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	h.app.setAuth(ghapi.Token{AccessToken: "gho_old"}, "octocat", true, true)
	before := h.app.AuthState()
	h.events.reset()
	entered := make(chan struct{})
	h.app.restoreSession = func(ctx context.Context, _ ghapi.Keyring, _ string) (ghapi.Token, string, bool, bool, error) {
		close(entered)
		<-ctx.Done()
		// RestoreSession reports a cancelled validation as offline.
		return ghapi.Token{AccessToken: "gho_other"}, "", true, true, nil
	}
	noDeviceFlow(t, h.app)

	done := make(chan error, 1)
	go func() {
		_, err := h.app.Login(context.Background())
		done <- err
	}()
	<-entered
	h.app.CancelLogin()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Login err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Login did not return after cancel")
	}
	if st := h.app.AuthState(); st != before {
		t.Errorf("state = %+v, want unchanged %+v", st, before)
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
	h.app.mu.Lock()
	tok := h.app.token.AccessToken
	h.app.mu.Unlock()
	if tok != "gho_old" {
		t.Errorf("token = %q, want the old one kept", tok)
	}
}

func TestLogout(t *testing.T) {
	kr := ghapi.NewFakeKeyring()
	h := newAppHarness(t, kr)
	if err := ghapi.SaveToken(kr, h.dir, ghapi.Token{AccessToken: "gho_old", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h.app.setAuth(ghapi.Token{AccessToken: "gho_old"}, "octocat", true, true)
	h.events.reset()

	h.app.Logout()

	if h.app.AuthState() != (AuthState{}) || h.app.githubClient() != nil {
		t.Errorf("state = %+v, want logged out", h.app.AuthState())
	}
	if _, err := ghapi.LoadToken(kr, h.dir); err == nil {
		t.Error("saved token not cleared")
	}
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventAuthChanged}) {
		t.Errorf("events = %v", names)
	}
}

func TestLogin_NoKeyring(t *testing.T) {
	h := newAppHarness(t, nil)
	noDeviceFlow(t, h.app)
	h.app.restoreSession = func(context.Context, ghapi.Keyring, string) (ghapi.Token, string, bool, bool, error) {
		t.Error("restore attempted")
		return ghapi.Token{}, "", false, false, nil
	}

	st, err := h.app.Login(context.Background())
	if !errors.Is(err, ErrLoginUnavailable) || err.Error() != "GitHub login isn't available: no secure credential store on this computer." {
		t.Errorf("Login err = %v, want the no-keyring message", err)
	}
	if st != (AuthState{}) || h.app.AuthState() != (AuthState{}) {
		t.Errorf("state = %+v / %+v, want logged out", st, h.app.AuthState())
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
}

func TestLogout_NoKeyring(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.setAuth(ghapi.Token{AccessToken: "gho_old"}, "octocat", true, false)
	h.events.reset()

	h.app.Logout()

	if h.app.AuthState() != (AuthState{}) || h.app.githubClient() != nil {
		t.Errorf("state = %+v, want logged out", h.app.AuthState())
	}
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventAuthChanged}) {
		t.Errorf("events = %v", names)
	}
	if strings.Contains(h.debugLog(t), "clearing token failed") {
		t.Error("Logout without a keyring logged a clear failure")
	}
}

func TestLogout_ClearFailureLogged(t *testing.T) {
	kr := ghapi.NewFakeKeyring()
	h := newAppHarness(t, kr)
	kr.SimulateError = errors.New("keyring locked")
	h.app.Logout()
	if !strings.Contains(h.debugLog(t), "warning: clearing token failed: keyring locked") {
		t.Error("clear failure not logged")
	}
}

func TestGithubClient(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	for _, tc := range []struct {
		name              string
		token             string
		user              string
		loggedIn, offline bool
		wantClient        bool
	}{
		{"logged out", "tok", "u", false, false, false},
		{"offline", "tok", "u", true, true, false},
		{"empty token", "", "u", true, false, false},
		{"empty username", "tok", "", true, false, true},
	} {
		h.app.setAuth(ghapi.Token{AccessToken: tc.token}, tc.user, tc.loggedIn, tc.offline)
		c := h.app.githubClient()
		if (c != nil) != tc.wantClient {
			t.Errorf("%s: client = %v, want non-nil %v", tc.name, c, tc.wantClient)
		}
		if c != nil && (c.Owner != ghapi.DefaultOwner || c.Repo != ghapi.DefaultRepo) {
			t.Errorf("%s: client repo = %s/%s", tc.name, c.Owner, c.Repo)
		}
	}
}

func TestStart_RestoreThenFetch(t *testing.T) {
	srv := registryServer(t, http.StatusOK)
	dir := t.TempDir()
	events := &fakeEvents{}
	app, err := New(Config{
		DataDir:     dir,
		Logger:      debuglog.New(filepath.Join(dir, debuglog.FileName)),
		RegistryURL: srv.URL,
		Keyring:     ghapi.NewFakeKeyring(),
		Prompter:    newFakePrompter("", false),
		Events:      events,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer app.Close()
	app.Start()
	events.waitFor(t, EventRegistryChanged)
	// RefreshHistory runs alongside; wait for it so it is not still logging
	// when the test's temp dir is removed.
	events.waitFor(t, EventRevocationsChanged)

	names, _ := events.snapshot()
	var startup []string
	for _, n := range names {
		if n == EventAuthChanged || n == EventRegistryChanged {
			startup = append(startup, n)
		}
	}
	if !reflect.DeepEqual(startup, []string{EventAuthChanged, EventRegistryChanged}) {
		t.Errorf("events = %v, want auth then registry", names)
	}
	snap := app.Registry()
	if !snap.Loaded || snap.Dirty || len(snap.Entries) != 2 {
		t.Errorf("snapshot = %+v, want 2 loaded entries", snap)
	}
}

func TestStartupRestore(t *testing.T) {
	t.Run("fetch fails", func(t *testing.T) {
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		stubRestore(h.app, ghapi.Token{AccessToken: "t"}, "", true, true, nil)
		h.app.startupRestore()
		if names := eventNames(h); !reflect.DeepEqual(names, []string{EventAuthChanged, EventRegistryChanged}) {
			t.Errorf("events = %v", names)
		}
		if h.app.Registry().Loaded {
			t.Error("Loaded = true after failed fetch")
		}
		if h.app.AuthState() != (AuthState{LoggedIn: true, Offline: true}) {
			t.Errorf("state = %+v", h.app.AuthState())
		}
		if !strings.Contains(h.debugLog(t), "error: registry fetch failed") {
			t.Error("fetch failure not logged")
		}
	})
	t.Run("already loaded keeps edits", func(t *testing.T) {
		// A FetchRegistry finished while the restore ran, then an edit.
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		stubRestore(h.app, ghapi.Token{}, "", false, false, nil)
		h.app.registryURL = registryServer(t, http.StatusOK).URL // a fetch would succeed
		markLoaded(h)
		if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
			t.Fatal(err)
		}
		h.app.startupRestore()
		if snap := h.app.Registry(); !snap.Dirty || len(snap.Entries) != 1 {
			t.Errorf("startup fetch clobbered the edit: %+v", snap)
		}
	})
	t.Run("loaded during the startup fetch keeps edits", func(t *testing.T) {
		// A FetchRegistry and an edit land while the startup fetch is in flight.
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		stubRestore(h.app, ghapi.Token{}, "", false, false, nil)
		site := registryServer(t, http.StatusOK)
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			markLoaded(h)
			if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
				t.Error(err)
			}
			resp, err := http.Get(site.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			_, _ = io.Copy(w, resp.Body)
		}))
		t.Cleanup(proxy.Close)
		h.app.registryURL = proxy.URL
		h.app.startupRestore()
		if snap := h.app.Registry(); !snap.Dirty || len(snap.Entries) != 1 {
			t.Errorf("startup fetch clobbered the edit: %+v", snap)
		}
		if strings.Contains(h.debugLog(t), "error: registry fetch failed") {
			t.Error("startup fetch failed; the test did not exercise the race")
		}
	})
	t.Run("logged in loads main via the API", func(t *testing.T) {
		reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "From API", nil)}}
		up, err := marshalRegistry(reg)
		if err != nil {
			t.Fatal(err)
		}
		_, client := newSubmitFake(t, up, http.StatusOK)
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		h.app.registryURL = registryServer(t, http.StatusOK).URL // the site copy has 2 other keys
		h.app.newClient = func(string) *ghapi.Client { return client }
		stubRestore(h.app, ghapi.Token{AccessToken: "t"}, "u", true, false, nil)
		h.app.startupRestore()
		if e := h.app.Registry().Entries; len(e) != 1 || e[0].Authority != "From API" {
			t.Errorf("entries = %+v, want the API copy", e)
		}
	})
}

func TestLogin_DeviceFlowMessages(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ghapi.ErrDeviceCodeExpired, "The login code expired. Start the login again to get a new one."},
		{ghapi.ErrAccessDenied, "GitHub access was denied, so you are not logged in."},
		{ghapi.ErrMissingScope, "GitHub didn't grant the public_repo permission the app needs. Log in again and approve it."},
		{errors.New("other"), "An error occurred. Please try again later."},
	} {
		h := newAppHarness(t, ghapi.NewFakeKeyring())
		stubDeviceFlow(h.app, "https://github.com/login/device", nil, "", nil)
		h.app.pollForToken = func(context.Context, string, int, int) (ghapi.Token, error) {
			return ghapi.Token{}, tc.err
		}
		_, err := h.app.Login(context.Background())
		if err == nil || err.Error() != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("poll %v: err = %v, want %q", tc.err, err, tc.want)
		}
	}
}
