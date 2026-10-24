//go:build rhgfake

package rpc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/host"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// The rhgfake test build runs real flows with no YubiKey and never writes to
// GitHub: the App signs with service's fake card (PIN service.FakeCardPIN),
// host.NewService drops its keyring (so no GitHub login, submit or revoke, and
// Report Issue opens the browser form), the update manager does nothing, and the registry
// is unreachable unless test.configure serves one on loopback. It adds two
// methods, outside methodTable and allowed in every state:
//
//	test.configure {online, pinTimeoutMs} — only before app.init. online
//	  serves a registry holding the fake card's key and an empty revocation
//	  list; pinTimeoutMs > 0 replaces the PIN prompt timeout.
//	test.panic {} — panics, to exercise the internal error path.

// deadURL is a registry and revocation URL that refuses connections.
const deadURL = "http://127.0.0.1:1"

// fakeAuthority is the fake card's authority in the served registry.
const fakeAuthority = "RHG Test Card"

var (
	errConfigureLate = &inputError{"Configure the test build before initializing the app."}
	errBadPINTimeout = &inputError{"pinTimeoutMs must not be negative."}
)

// testPanicValue is test.panic's panic value.
const testPanicValue = "rpc: test.panic"

type testConfigureParams struct {
	Online       bool `json:"online"`
	PINTimeoutMs int  `json:"pinTimeoutMs"`
}

func init() {
	anyStateMethods["test.configure"] = true
	anyStateMethods["test.panic"] = true
}

// addTestMethods adds test.configure and test.panic to s and replaces its
// update manager and service constructor with the test build's.
func addTestMethods(s *server) {
	s.methods["test.configure"] = method((*server).configureTest)
	s.methods["test.panic"] = noParams(func(*server) (any, error) { panic(testPanicValue) })
	s.newManager = func(update.Config) updateManager { return idleManager{} }
	s.newService = testService(deadURL, deadURL, 0)
}

// configureTest is test.configure: it sets the service constructor app.init
// will use.
func (s *server) configureTest(p testConfigureParams) (any, error) {
	if p.PINTimeoutMs < 0 {
		return nil, errBadPINTimeout
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateNew {
		return nil, errConfigureLate
	}
	registryURL, revocationURL := deadURL, deadURL
	if p.Online {
		base := fakeRegistryServer()
		registryURL, revocationURL = base+"/registry", base+"/revocations"
	}
	s.newService = testService(registryURL, revocationURL, time.Duration(p.PINTimeoutMs)*time.Millisecond)
	return struct{}{}, nil
}

// testService returns a service constructor using the given registry and
// revocation URLs and, when pinTimeout > 0, that PIN prompt timeout.
func testService(registryURL, revocationURL string, pinTimeout time.Duration) func(service.Config) (*service.App, error) {
	return func(cfg service.Config) (*service.App, error) {
		cfg.RegistryURL, cfg.RevocationURL = registryURL, revocationURL
		app, err := host.NewService(cfg)
		if err == nil && pinTimeout > 0 {
			service.SetPINTimeoutForTest(app, pinTimeout)
		}
		return app, err
	}
}

// fakeRegistryServer starts, on first use, the process's loopback registry
// server and returns its base URL. It serves /registry (the fake card's key,
// active from 2000-01-01 with no end) and /revocations (empty), and runs for
// the rest of the process.
var fakeRegistryServer = sync.OnceValue(func() string {
	pub := service.FakeCardPublicKey()
	registry := `{"keys": [{"authority": "` + fakeAuthority + `", "from": "2000-01-01", "to": null, "algorithm": "Ed25519", "public_key": "` +
		base64.StdEncoding.EncodeToString(pub[:]) + `", "note": ""}]}`
	docs := map[string]string{"/registry": registry, "/revocations": `{"revocations":[]}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return srv.URL
})

// idleManager is the test build's update manager: it never checks or
// installs anything.
type idleManager struct{}

func (idleManager) Run(ctx context.Context) { <-ctx.Done() }
func (idleManager) ApplyIfReady(bool)       {}
