package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
)

func validForm() EntryForm {
	return EntryForm{Authority: " Authority A ", From: "2026-01-01", To: "2027-01-01", Note: "n"}
}

// loadRegistry fetches reg into h's edit registry from a Pages-style server.
func loadRegistry(t *testing.T, h *appHarness, reg core.Registry) {
	t.Helper()
	data, err := marshalRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	h.app.registryURL = srv.URL
	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatalf("FetchRegistry: %v", err)
	}
	h.events.reset()
}

// logIn puts h in the logged-in state with newClient returning client.
func logIn(h *appHarness, client *ghapi.Client) {
	h.app.newClient = func(string) *ghapi.Client { return client }
	h.app.setAuth(ghapi.Token{AccessToken: "tok"}, "octocat", true, false)
	h.events.reset()
}

func TestAddEntry(t *testing.T) {
	h := newAppHarness(t, nil)
	key := testKeyB64(1)

	if err := h.app.AddEntry(EntryForm{From: "2026-01-01", NoExpiry: true}, key); err == nil || err.Error() != "Authority is required" {
		t.Errorf("err = %v, want the validation message", err)
	}
	if h.app.Registry().Dirty || h.app.Dirty() {
		t.Error("a rejected add must not mark the registry dirty")
	}

	if err := h.app.AddEntry(validForm(), key); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	noExpiry := validForm()
	noExpiry.NoExpiry = true
	if err := h.app.AddEntry(noExpiry, key); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}

	snap := h.app.Registry()
	if !snap.Dirty || snap.Loaded || !h.app.Dirty() || len(snap.Entries) != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
	e := snap.Entries[0]
	if e.Authority != "Authority A" || e.To == nil || *e.To != "2027-01-01" || e.PublicKey != key || e.Algorithm != core.SupportedAlgorithm {
		t.Errorf("entry = %+v", e)
	}
	if snap.Entries[1].To != nil {
		t.Error("NoExpiry entry has a To date")
	}
	fp, _ := core.KeyFingerprint(e)
	want := []string{"1", "Authority A", core.FormatDateDisplay("2026-01-01"), core.FormatDateDisplay("2027-01-01"), "(none)", "n", fp}
	if !reflect.DeepEqual(snap.Rows[0], want) {
		t.Errorf("row = %v, want %v", snap.Rows[0], want)
	}
	if snap.Rows[1][3] != "(none)" {
		t.Errorf("no-expiry To cell = %q", snap.Rows[1][3])
	}
}

func TestRegistry_InvalidKeyAndCopy(t *testing.T) {
	h := newAppHarness(t, nil)
	if err := h.app.AddEntry(validForm(), "not-a-key"); err != nil {
		t.Fatal(err)
	}
	snap := h.app.Registry()
	if snap.Rows[0][6] != "(invalid key)" {
		t.Errorf("fingerprint cell = %q", snap.Rows[0][6])
	}
	snap.Entries[0].Authority = "mutated"
	if h.app.Registry().Entries[0].Authority != "Authority A" {
		t.Error("Registry did not return a copy")
	}
}

func TestUpdateEntry(t *testing.T) {
	h := newAppHarness(t, nil)
	key := testKeyB64(1)
	extra := map[string]json.RawMessage{"allowed_honors": json.RawMessage(`["Other"]`)}
	loadRegistry(t, h, core.Registry{Keys: []core.KeyEntry{{Authority: "A", From: "2025-01-01", Algorithm: core.SupportedAlgorithm, PublicKey: key, Extra: extra}}})
	before := h.app.Registry()

	for name, call := range map[string]func() error{
		"mismatched key": func() error { return h.app.UpdateEntry(0, testKeyB64(2), validForm()) },
		"out of range":   func() error { return h.app.UpdateEntry(1, key, validForm()) },
		"negative":       func() error { return h.app.UpdateEntry(-1, key, validForm()) },
		"invalid form":   func() error { return h.app.UpdateEntry(0, key, EntryForm{Authority: "A"}) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: err = nil", name)
		}
		if !reflect.DeepEqual(h.app.Registry(), before) {
			t.Errorf("%s: registry changed", name)
		}
	}

	if err := h.app.UpdateEntry(0, key, validForm()); err != nil {
		t.Fatalf("UpdateEntry: %v", err)
	}
	snap := h.app.Registry()
	e := snap.Entries[0]
	if !snap.Dirty || e.Authority != "Authority A" || e.Note != "n" || !reflect.DeepEqual(e.Extra, before.Entries[0].Extra) || e.Extra == nil {
		t.Errorf("updated = %+v, dirty %v", e, snap.Dirty)
	}
	if snap.Rows[0][4] != "Other" {
		t.Errorf("restrictions cell = %q", snap.Rows[0][4])
	}
}

func TestFetchRegistry_LoggedOut(t *testing.T) {
	h := newAppHarness(t, nil)
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	srv := registryServer(t, http.StatusOK)
	h.app.registryURL = srv.URL

	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatalf("FetchRegistry: %v", err)
	}
	snap := h.app.Registry()
	if snap.Dirty || !snap.Loaded || len(snap.Entries) != 2 || snap.Entries[0].Authority != "A" {
		t.Errorf("snapshot = %+v, want the fetched registry", snap)
	}
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventRegistryChanged}) {
		t.Errorf("events = %v", names)
	}
}

func TestFetchRegistry_Failure(t *testing.T) {
	h := newAppHarness(t, nil)
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	h.app.registryURL = registryServer(t, http.StatusInternalServerError).URL

	if err := h.app.FetchRegistry(context.Background()); err == nil {
		t.Fatal("err = nil")
	}
	if snap := h.app.Registry(); !snap.Dirty || len(snap.Entries) != 1 {
		t.Errorf("failed fetch changed the registry: %+v", snap)
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
	if !strings.Contains(h.debugLog(t), "error: registry fetch failed") {
		t.Error("failure not logged")
	}
}

func TestFetchRegistry_LoggedInUsesAPIThenFallsBack(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Main copy", nil)}}
	up, err := marshalRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	h := newAppHarness(t, nil)
	h.app.registryURL = registryServer(t, http.StatusOK).URL

	_, client := newSubmitFake(t, up, http.StatusOK)
	logIn(h, client)
	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatalf("FetchRegistry: %v", err)
	}
	if got := h.app.Registry().Entries; len(got) != 1 || got[0].Authority != "Main copy" {
		t.Errorf("entries = %+v, want main via the API", got)
	}

	_, failing := newSubmitFake(t, nil, http.StatusInternalServerError)
	logIn(h, failing)
	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatalf("FetchRegistry: %v", err)
	}
	if got := h.app.Registry().Entries; len(got) != 2 {
		t.Errorf("entries = %+v, want the site copy", got)
	}
	if !strings.Contains(h.debugLog(t), "warning: registry fetch from GitHub failed, using site copy") {
		t.Error("API failure not logged")
	}
}

func TestImportCertificate(t *testing.T) {
	h := newAppHarness(t, nil)
	key, err := h.app.ImportCertificate("../testdata/test-ed25519.crt")
	if err != nil || len(key) != 44 {
		t.Errorf("ImportCertificate = %q, %v", key, err)
	}

	if _, err := h.app.ImportCertificate(filepath.Join(h.dir, "missing.crt")); err == nil || !strings.HasPrefix(err.Error(), "Failed to read file: ") {
		t.Errorf("missing file err = %v", err)
	}

	bad := filepath.Join(h.dir, "bad.crt")
	if err := os.WriteFile(bad, []byte("garbage\x1b[31m"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.ImportCertificate(bad); err == nil || !strings.HasPrefix(err.Error(), "not a valid certificate") {
		t.Errorf("bad cert err = %v", err)
	}
}

func TestImportFromYubiKey(t *testing.T) {
	h := newAppHarness(t, nil)
	key, err := h.app.ImportFromYubiKey()
	want, _ := (&mockSignAdapter{secretKey: h.priv}).ExportPublicKey()
	if err != nil || key != base64.StdEncoding.EncodeToString(want[:]) {
		t.Errorf("ImportFromYubiKey = %q, %v", key, err)
	}

	h.openErr = errors.New("no YubiKey found")
	if _, err := h.app.ImportFromYubiKey(); err == nil || err.Error() != importKeyErrorMessage(h.openErr) {
		t.Errorf("open error = %v", err)
	}
	if !strings.Contains(h.debugLog(t), "yubikey import: no YubiKey found") {
		t.Error("open error not logged")
	}

	h.openErr = nil
	h.signer = func(ed25519.PrivateKey) core.SigningAdapter { return &errorExportAdapter{} }
	if _, err := h.app.ImportFromYubiKey(); err == nil || err.Error() != importKeyErrorMessage(fmt.Errorf("hardware failure")) {
		t.Errorf("export error = %v", err)
	}

	h.app.busy.Store(true)
	defer h.app.busy.Store(false)
	if _, err := h.app.ImportFromYubiKey(); !errors.Is(err, ErrBusy) {
		t.Errorf("busy err = %v, want ErrBusy", err)
	}
}

func TestSubmitRegistry_Preconditions(t *testing.T) {
	h := newAppHarness(t, nil)
	if _, err := h.app.SubmitRegistry(context.Background()); err == nil || errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("empty registry err = %v", err)
	}
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.SubmitRegistry(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("logged out err = %v, want ErrNotLoggedIn", err)
	}
	h.app.setAuth(ghapi.Token{AccessToken: "tok"}, "", true, true)
	if _, err := h.app.SubmitRegistry(context.Background()); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("offline err = %v, want ErrNotLoggedIn", err)
	}
}

func TestSubmitRegistry_SuccessClearsDirty(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	up, err := marshalRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	h := newAppHarness(t, nil)
	_, client := newSubmitFake(t, up, http.StatusOK)
	logIn(h, client)
	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}

	pr, err := h.app.SubmitRegistry(context.Background())
	if err != nil || pr.Number != 7 {
		t.Fatalf("SubmitRegistry = %+v, %v", pr, err)
	}
	if h.app.Dirty() || h.app.Registry().Dirty {
		t.Error("dirty not cleared after submit")
	}
}

func TestSubmitRegistry_ErrorKeepsDirty(t *testing.T) {
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	_, client := newSubmitFake(t, nil, http.StatusUnauthorized)
	logIn(h, client)
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.SubmitRegistry(context.Background()); !ghapi.IsUnauthorized(err) {
		t.Errorf("err = %v, want unauthorized", err)
	}
	if !h.app.Dirty() {
		t.Error("failed submit cleared dirty")
	}
	if h.app.AuthState().LoggedIn {
		t.Error("401 did not log out")
	}
	if !strings.Contains(h.debugLog(t), "warning: registry submit unauthorized") {
		t.Error("401 not logged")
	}
}

// hookTransport runs hook once, before the first request it carries.
type hookTransport struct {
	rt   http.RoundTripper
	once sync.Once
	hook func()
}

func (h *hookTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	h.once.Do(h.hook)
	return h.rt.RoundTrip(r)
}

func TestSubmitRegistry_EditDuringSubmitStaysDirty(t *testing.T) {
	reg := core.Registry{Keys: []core.KeyEntry{testKeyEntry(t, "Key X", nil)}}
	up, err := marshalRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	h := newAppHarness(t, nil)
	_, client := newSubmitFake(t, up, http.StatusOK)
	logIn(h, client)
	if err := h.app.FetchRegistry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	// An edit lands after the submit copied the registry.
	client.HTTPClient.Transport = &hookTransport{rt: client.HTTPClient.Transport, hook: func() {
		if err := h.app.AddEntry(validForm(), testKeyB64(2)); err != nil {
			t.Error(err)
		}
	}}

	if _, err := h.app.SubmitRegistry(context.Background()); err != nil {
		t.Fatalf("SubmitRegistry: %v", err)
	}
	if !h.app.Dirty() {
		t.Error("edit made during the submit was marked submitted")
	}
}

func TestSubmitRegistry_ConcurrentBusy(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client := ghapi.NewClient("tok")
	client.HTTPClient.Transport = &rewriteTransport{base: http.DefaultTransport, targetURL: srv.URL}

	h := newAppHarness(t, nil)
	logIn(h, client)
	if err := h.app.AddEntry(validForm(), testKeyB64(1)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.app.SubmitRegistry(context.Background())
		done <- err
	}()
	<-entered
	if _, err := h.app.SubmitRegistry(context.Background()); !errors.Is(err, ErrBusy) {
		t.Errorf("second submit err = %v, want ErrBusy", err)
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Error("first submit err = nil, want the server error")
		}
		if !strings.Contains(h.debugLog(t), "error: PR submission failed") {
			t.Error("submit failure not logged")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first submit did not return")
	}
}

func TestSubmitErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		err              error
		wantTitle, inMsg string
	}{
		{fmt.Errorf("x: %w", &ghapi.APIError{StatusCode: 401}), "Session Expired", "session expired"},
		{fmt.Errorf("x: %w", ErrRegistryChanged), "Registry Changed", "Fetch from Server"},
		{&ghapi.APIError{StatusCode: 429}, "Submission Failed", "rate limit"},
		{errors.New("timeout"), "Submission Failed", "try again later"},
	} {
		title, msg := SubmitErrorMessage(tc.err)
		if title != tc.wantTitle || !strings.Contains(msg, tc.inMsg) {
			t.Errorf("%v: got %q / %q", tc.err, title, msg)
		}
	}
}
