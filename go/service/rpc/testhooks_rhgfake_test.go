//go:build rhgfake

package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// fakeHarness is a server exactly as the rhgfake build makes it, with an
// event sink attached.
type fakeHarness struct {
	srv  *server
	sink *eventSink
	dir  string // app.init's data dir

	// onEvent, when set, runs on every event after it is recorded, on the
	// emitting goroutine.
	mu      sync.Mutex
	onEvent func(name string, data json.RawMessage)
}

func newFakeHarness(t *testing.T) *fakeHarness {
	t.Helper()
	h := &fakeHarness{srv: newServer(), sink: newEventSink(), dir: filepath.Join(t.TempDir(), "data")}
	h.srv.events.SetSink(func(b []byte) {
		h.sink.add(b)
		h.mu.Lock()
		f := h.onEvent
		h.mu.Unlock()
		if f == nil {
			return
		}
		var ev struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if json.Unmarshal(b, &ev) == nil {
			f(ev.Event, ev.Data)
		}
	})
	cleanupServer(t, h.srv)
	return h
}

func (h *fakeHarness) call(t testing.TB, method, params string) envelope {
	t.Helper()
	return dispatch(t, h.srv, method, params)
}

// init runs app.init and returns its info.
func (h *fakeHarness) init(t testing.TB) service.Info {
	t.Helper()
	var info service.Info
	h.call(t, "app.init", `{"dataDir":`+jsonString(h.dir)+`}`).ok(t, &info)
	return info
}

func (h *fakeHarness) setOnEvent(f func(name string, data json.RawMessage)) {
	h.mu.Lock()
	h.onEvent = f
	h.mu.Unlock()
}

// answerPIN makes h answer every pin.request with pin, from the event
// callback itself (pin.submit never blocks).
func (h *fakeHarness) answerPIN(pin string) *[]string {
	var mu sync.Mutex
	var failures []string
	h.setOnEvent(func(name string, data json.RawMessage) {
		if name != EventPINRequest {
			return
		}
		var req struct {
			RequestID uint64 `json:"requestId"`
		}
		_ = json.Unmarshal(data, &req)
		params, _ := json.Marshal(map[string]any{"requestId": req.RequestID, "pin": pin, "remember": false})
		if out := h.srv.Dispatch("pin.submit", params); !bytes.HasPrefix(out, []byte(`{"ok":true`)) {
			mu.Lock()
			failures = append(failures, string(out))
			mu.Unlock()
		}
	})
	return &failures
}

func TestTestMethods_OutsideMethodTable(t *testing.T) {
	table := methodTable()
	srv := newServer()
	for _, name := range []string{"test.configure", "test.panic"} {
		if table[name] != nil {
			t.Errorf("%s is in methodTable", name)
		}
		if srv.methods[name] == nil || !anyStateMethods[name] {
			t.Errorf("%s is not an any-state method of the rhgfake server", name)
		}
	}
}

// TestFakeBuild_NoGitHubLogin: with no keyring, a test build can't log in,
// so it has no session to submit a registry change or revoke with.
func TestFakeBuild_NoGitHubLogin(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	h.init(t)
	h.call(t, "auth.login", ``).fails(t, CodeLoginUnavailable, "")
}

func TestFakeBuild_Defaults(t *testing.T) {
	srv := newServer()
	m := srv.newManager(update.Config{})
	if _, ok := m.(idleManager); !ok {
		t.Fatalf("update manager = %T, want idleManager", m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	m.ApplyIfReady(true)
	cancel()
	<-done
}

func TestConfigure_DefaultIsOffline(t *testing.T) {
	h := newFakeHarness(t)
	if info := h.init(t); info.Online || info.ActiveKeys != 0 {
		t.Fatalf("info = %+v, want offline", info)
	}
}

func TestConfigure_Offline(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":false}`).ok(t, nil)
	if info := h.init(t); info.Online {
		t.Fatalf("info = %+v, want offline", info)
	}
}

func TestConfigure_OnlyBeforeInit(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{}`).ok(t, nil)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil) // reconfigure while new
	h.init(t)
	h.call(t, "test.configure", `{}`).fails(t, CodeInput, errConfigureLate.msg)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	h.call(t, "test.configure", `{}`).fails(t, CodeInput, errConfigureLate.msg)
}

func TestConfigure_RejectsBadParams(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"pinTimeoutMs":-1}`).fails(t, CodeInput, errBadPINTimeout.msg)
	h.call(t, "test.configure", `{"online":true,"pin":"1"}`).fails(t, CodeInput, msgBadParams)
	h.call(t, "test.panic", `{"x":1}`).fails(t, CodeInput, msgBadParams)
}

func TestConfigure_OnlineSignRoundTrip(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	if info := h.init(t); !info.Online || info.ActiveKeys != 1 {
		t.Fatalf("info = %+v, want online with 1 active key", info)
	}
	failures := h.answerPIN(service.FakeCardPIN)
	var res service.SignResult
	h.call(t, "sign.sign", validSign).ok(t, &res)
	if len(*failures) != 0 {
		t.Fatalf("pin.submit failed: %v", *failures)
	}
	if res.URL == "" || res.Existing {
		t.Fatalf("sign result = %+v", res)
	}
	if n := len(h.sink.named(t, EventPINRequest)); n != 1 {
		t.Fatalf("%d pin.request events, want 1", n)
	}

	// The logged signature verifies with the fake card's key.
	recs, err := issuancelog.ReadLog(filepath.Join(h.dir, "issuances.json"))
	if err != nil || len(recs) != 1 {
		t.Fatalf("issuance log = %v, %v", recs, err)
	}
	payload, err := core.BuildPayload(core.SignRequest{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(recs[0].SignatureB64URL)
	if err != nil {
		t.Fatal(err)
	}
	pub := service.FakeCardPublicKey()
	if !ed25519.Verify(pub[:], payload, sig) {
		t.Fatal("signature does not verify with the fake card's key")
	}

	// The fake card's key is the registry's active key.
	var check service.KeyCheck
	h.call(t, "yubikey.check", ``).ok(t, &check)
	if check.Outcome != service.KeyCheckFound {
		t.Errorf("yubikey.check = %+v, want found", check)
	}

	for _, e := range h.sink.all() {
		if strings.Contains(e, service.FakeCardPIN) {
			t.Errorf("event carries the PIN: %s", e)
		}
	}
}

func TestConfigure_WrongPIN(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	h.init(t)
	h.answerPIN("000000")
	env := h.call(t, "sign.sign", validSign)
	if env.OK || env.Error.Code != CodeFailed || env.Error.OfferReport ||
		!strings.HasPrefix(env.Error.Message, "Incorrect PIN") {
		t.Fatalf("sign.sign with a wrong PIN = %s", env.raw)
	}
}

func TestConfigure_PINTimeout(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true,"pinTimeoutMs":50}`).ok(t, nil)
	h.init(t)
	env := h.call(t, "sign.sign", validSign) // nobody answers
	if env.OK || env.Error.Code != CodeFailed || env.Error.OfferReport ||
		env.Error.Message != "PIN entry timed out. Try again." {
		t.Fatalf("sign.sign without a PIN = %s", env.raw)
	}
	req := h.sink.wait(t, EventPINRequest, 1)
	dismiss := h.sink.wait(t, EventPINDismiss, 1)
	var r, d struct {
		RequestID uint64 `json:"requestId"`
	}
	if json.Unmarshal(req, &r) != nil || json.Unmarshal(dismiss, &d) != nil || r.RequestID != d.RequestID || r.RequestID == 0 {
		t.Fatalf("pin.request %s, pin.dismiss %s", req, dismiss)
	}
}

func TestTestPanic(t *testing.T) {
	h := newFakeHarness(t)
	want := string(InternalEnvelope())
	if env := h.call(t, "test.panic", ``); env.raw != want {
		t.Fatalf("test.panic before init = %s, want %s", env.raw, want)
	}
	h.init(t)
	if env := h.call(t, "test.panic", `{}`); env.raw != want {
		t.Fatalf("test.panic = %s, want %s", env.raw, want)
	}
	h.call(t, "app.canQuit", ``).ok(t, nil)
	h.call(t, "app.shutdown", ``).ok(t, nil)
	if env := h.call(t, "test.panic", ``); env.raw != want {
		t.Fatalf("test.panic after shutdown = %s", env.raw)
	}
}

func TestFakeRegistryServer(t *testing.T) {
	base := fakeRegistryServer()
	if fakeRegistryServer() != base {
		t.Fatal("a second call started another server")
	}
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("server %s is not on loopback", base)
	}
	resp, err := http.Get(base + "/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/other: %d, want 404", resp.StatusCode)
	}
	reg, err := http.Get(base + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Body.Close()
	var body struct {
		Keys []struct {
			Authority string `json:"authority"`
			From      string `json:"from"`
			To        *string
		} `json:"keys"`
	}
	if err := json.NewDecoder(reg.Body).Decode(&body); err != nil || len(body.Keys) != 1 ||
		body.Keys[0].Authority != fakeAuthority || body.Keys[0].From != "2000-01-01" || body.Keys[0].To != nil {
		t.Fatalf("registry = %+v, %v", body, err)
	}
}

// TestFakeSign_PINCancelled: a pin.cancel answer is CodeCancelled with the
// cancel text, not a SignError.
func TestFakeSign_PINCancelled(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	h.init(t)
	h.setOnEvent(func(name string, data json.RawMessage) {
		if name == EventPINRequest {
			var req pinRequestEvent
			_ = json.Unmarshal(data, &req)
			params, _ := json.Marshal(pinCancelParams{RequestID: req.RequestID})
			h.srv.Dispatch("pin.cancel", params)
		}
	})
	env := h.call(t, "sign.sign", validSign)
	env.fails(t, CodeCancelled, "")
	// errors/cancelled.json goes through the error encoder (a cancel needs a
	// card), so pin it to the real envelope here.
	var got, want any
	if json.Unmarshal([]byte(env.raw), &got) != nil || json.Unmarshal(readContract(t)["errors/cancelled.json"], &want) != nil ||
		!reflect.DeepEqual(got, want) {
		t.Errorf("sign.sign cancel = %s, want errors/cancelled.json", env.raw)
	}
}

// TestShutdown_PendingPIN: app.shutdown cancels a sign waiting at the PIN
// prompt, dismisses the prompt and stops event delivery.
func TestShutdown_PendingPIN(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	h.init(t)
	signDone := goDispatch(h.srv, "sign.sign", validSign)
	var req pinRequestEvent
	if err := json.Unmarshal(h.sink.wait(t, EventPINRequest, 1), &req); err != nil {
		t.Fatal(err)
	}
	if req.RequestID != 1 || req.MaxBytes != service.PIVMaxPINBytes {
		t.Errorf("pin.request = %+v", req)
	}

	h.call(t, "app.shutdown", ``).ok(t, nil)
	decodeEnvelope(t, "sign.sign", waitFor(t, signDone, "sign.sign returning after shutdown")).fails(t, CodeCancelled, "Signing cancelled.")
	if got := h.sink.named(t, EventPINDismiss); len(got) != 1 || string(got[0]) != `{"requestId":1}` {
		t.Errorf("pin.dismiss = %s", got)
	}
	n := len(h.sink.all())
	h.srv.events.Emit("late", nil)
	if len(h.sink.all()) != n {
		t.Error("event delivered after shutdown")
	}
}

// TestFakeBulk_BusyAndCancel: a bulk run waiting at the PIN prompt makes the
// other card calls busy until bulk.cancel, and ends cancelled.
func TestFakeBulk_BusyAndCancel(t *testing.T) {
	h := newFakeHarness(t)
	h.call(t, "test.configure", `{"online":true}`).ok(t, nil)
	h.init(t)
	csv := filepath.Join(t.TempDir(), "in.csv")
	writeFile(t, csv, "name,honor,detail,date\nJane Doe,Ennoblement,For service,2026-01-02\nBob,Bogus,x,2026-01-02\n")
	h.call(t, "bulk.load", `{"path":`+jsonString(csv)+`}`).ok(t, nil)

	done := goDispatch(h.srv, "bulk.run", ``)
	h.sink.wait(t, EventPINRequest, 1)
	busy := h.call(t, "yubikey.check", ``)
	busy.fails(t, CodeBusy, service.ErrBusy.Error())
	// errors/busy.json goes through the error encoder; pin it to this real
	// envelope as errors/cancelled.json is pinned in TestFakeSign_PINCancelled.
	var got, want any
	if json.Unmarshal([]byte(busy.raw), &got) != nil || json.Unmarshal(readContract(t)["errors/busy.json"], &want) != nil ||
		!reflect.DeepEqual(got, want) {
		t.Errorf("yubikey.check busy = %s, want errors/busy.json", busy.raw)
	}
	h.call(t, "bulk.load", `{"path":`+jsonString(csv)+`}`).fails(t, CodeBusy, "")
	h.call(t, "registry.importFromYubiKey", ``).fails(t, CodeBusy, "")
	h.call(t, "bulk.cancel", ``).ok(t, nil)

	var outcome service.BulkOutcome
	decodeEnvelope(t, "bulk.run", waitFor(t, done, "bulk.run returning after bulk.cancel")).ok(t, &outcome)
	if outcome.Stopped != service.BulkCancelled || outcome.StopMessage != "Cancelled." {
		t.Errorf("outcome = %+v", outcome)
	}
}

// TestYubiKey checks yubikey.check and registry.importFromYubiKey against the
// software card (a release-build test would read whatever real card is
// plugged in). The harness registry doesn't hold the fake card's key.
func TestYubiKey(t *testing.T) {
	h := newHarness(t, nil)
	var kc service.KeyCheck
	h.call(t, "yubikey.check", ``).ok(t, &kc)
	if kc.Outcome != service.KeyCheckNotFound || len(kc.Details) != 1 {
		t.Errorf("yubikey.check = %+v, want notFound with the fingerprint", kc)
	}
	var r struct{ PublicKey string }
	h.call(t, "registry.importFromYubiKey", ``).ok(t, &r)
	pub := service.FakeCardPublicKey()
	if r.PublicKey != base64.StdEncoding.EncodeToString(pub[:]) {
		t.Errorf("importFromYubiKey = %q, want the fake card's key", r.PublicKey)
	}
}
