package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// TestMain points HTTPS at a dead proxy so no test reaches GitHub: calls that
// would (the audit fetch, a device-code request) fail fast instead. The
// test servers are on loopback, which the proxy never applies to.
func TestMain(m *testing.M) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		os.Setenv(k, "http://127.0.0.1:1")
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		os.Setenv(k, "")
	}
	os.Exit(m.Run())
}

// cancelPrompter answers PIN requests with a cancel. Outside the rhgfake
// build no rpc test signs a new credential online (sign tests use an
// unreadable log, a logged credential or no registry), so neither the card
// nor this prompter is ever reached.
type cancelPrompter struct{}

func (p *cancelPrompter) RequestPIN(context.Context, bool) (string, bool, error) {
	return "", false, nil
}

// sinkRecorder collects emitted events.
type sinkRecorder struct {
	mu     sync.Mutex
	events [][]byte
}

func (r *sinkRecorder) add(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, append([]byte(nil), b...))
}

func (r *sinkRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	for i, e := range r.events {
		out[i] = string(e)
	}
	return out
}

type harness struct {
	srv      *server
	app      *service.App
	events   *jsonEvents
	sink     *sinkRecorder
	prompter *cancelPrompter
	dir      string // the App's data dir
	out      string // a folder to save to
}

// testKeyB64 is a deterministic base64 32-byte key.
func testKeyB64(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// newHarness builds an offline-from-GitHub App (registry and revocation list
// from a local test server) behind a server, with the rpc jsonEvents as its
// jsonEvents and a recorder as their sink.
func newHarness(t testing.TB, kr ghapi.Keyring) *harness {
	t.Helper()
	return newHarnessWith(t, kr, "")
}

// newHarnessWith is newHarness with revocations, when not "", served as the
// revocation list (else it is not found).
func newHarnessWith(t testing.TB, kr ghapi.Keyring, revocations string) *harness {
	t.Helper()
	body := `{"keys": [{"authority": "A", "from": "2025-01-01", "to": null, "algorithm": "Ed25519", "public_key": "` + testKeyB64(1) + `", "note": ""}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{"/registry": body, "/revocations": revocations}[r.URL.Path]
		if data == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(data))
	}))
	t.Cleanup(ts.Close)
	return newHarnessAt(t, kr, ts.URL+"/registry", ts.URL+"/revocations")
}

// newOfflineHarness is newHarness with an unreachable registry: the App
// starts offline.
func newOfflineHarness(t testing.TB) *harness {
	t.Helper()
	const dead = "http://127.0.0.1:1"
	return newHarnessAt(t, nil, dead, dead)
}

// newHarnessAt is newHarness with the given registry and revocation URLs.
func newHarnessAt(t testing.TB, kr ghapi.Keyring, registryURL, revocationURL string) *harness {
	t.Helper()
	dir := t.TempDir()
	logger := debuglog.New(filepath.Join(dir, debuglog.FileName))
	h := &harness{
		events:   newJSONEvents(logger),
		sink:     &sinkRecorder{},
		prompter: &cancelPrompter{},
		dir:      dir,
		out:      t.TempDir(),
	}
	h.events.SetSink(h.sink.add)
	app, err := service.New(service.Config{
		DataDir:       dir,
		Logger:        logger,
		RegistryURL:   registryURL,
		RevocationURL: revocationURL,
		Keyring:       kr,
		Prompter:      h.prompter,
		Events:        h.events,
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	t.Cleanup(app.Close)
	h.app = app
	h.srv = readyServer(app, logger)
	return h
}

// readyServer returns a server in stateReady around app, as app.init leaves
// it, without opening the process-wide logs.
func readyServer(app *service.App, logger *debuglog.Logger) *server {
	s := newServer()
	s.app, s.state = app, stateReady
	s.logger.Store(logger)
	return s
}

// envelope is a decoded Dispatch response.
type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		OfferReport bool   `json:"offerReport"`
		ReportID    string `json:"reportId"`
	} `json:"error"`
	raw string
}

func (h *harness) call(t testing.TB, method, params string) envelope {
	t.Helper()
	return dispatch(t, h.srv, method, params)
}

func dispatch(t testing.TB, s *server, method, params string) envelope {
	t.Helper()
	return decodeEnvelope(t, method, s.Dispatch(method, []byte(params)))
}

// goDispatch runs method on s in a new goroutine and delivers the raw
// envelope; the test goroutine decodes it with decodeEnvelope (t.Fatal is
// only valid there).
func goDispatch(s *server, method, params string) <-chan []byte {
	ch := make(chan []byte, 1)
	go func() { ch <- s.Dispatch(method, []byte(params)) }()
	return ch
}

// decodeEnvelope decodes out, method's envelope, failing t if it is
// malformed or inconsistent.
func decodeEnvelope(t testing.TB, method string, out []byte) envelope {
	t.Helper()
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("%s: envelope %s does not decode: %v", method, out, err)
	}
	env.raw = string(out)
	if env.OK != (env.Error == nil) || env.OK != (env.Result != nil) {
		t.Fatalf("%s: inconsistent envelope %s", method, out)
	}
	return env
}

// ok asserts env succeeded and decodes its result into v (if not nil).
func (env envelope) ok(t testing.TB, v any) {
	t.Helper()
	if !env.OK {
		t.Fatalf("want success, got %s", env.raw)
	}
	if v != nil {
		if err := json.Unmarshal(env.Result, v); err != nil {
			t.Fatalf("result %s: %v", env.Result, err)
		}
	}
}

// fails asserts env failed with code (and message, when not "").
func (env envelope) fails(t testing.TB, code, message string) {
	t.Helper()
	if env.OK || env.Error.Code != code || (message != "" && env.Error.Message != message) {
		t.Fatalf("want %s %q, got %s", code, message, env.raw)
	}
	if !env.Error.OfferReport && strings.Contains(env.raw, "reportId") {
		t.Fatalf("reportId without offerReport: %s", env.raw)
	}
}

func (h *harness) debugLog(t testing.TB) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.dir, debuglog.FileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t testing.TB, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRecords writes recs as the issuance log in dir.
func writeRecords(t testing.TB, dir string, recs []issuancelog.IssuanceRecord) {
	t.Helper()
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "issuances.json"), string(data))
}

func record(i int, recipient string) issuancelog.IssuanceRecord {
	return issuancelog.IssuanceRecord{
		Timestamp:       "2026-01-02T03:04:05Z",
		Recipient:       recipient,
		Honor:           "Ennoblement",
		Detail:          "For service",
		Date:            "2026-01-02",
		PayloadSHA256:   fmt.Sprintf("%064x", i),
		SignatureB64URL: strings.Repeat("A", 86),
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

const validSign = `{"recipient":"Jane Doe","honor":"Ennoblement","detail":"For service","date":"2026-01-02"}`

func TestDispatch_DecodingRules(t *testing.T) {
	h := newHarness(t, nil)
	long := func(n int) string { // a history.list params object of exactly n bytes
		return `{"query":"` + strings.Repeat("a", n-len(`{"query":""}`)) + `"}`
	}
	for _, tc := range []struct {
		name, method, params string
		wantOK               bool
	}{
		{"null", "history.list", `null`, false},
		{"array", "history.list", `[]`, false},
		{"string", "history.list", `"x"`, false},
		{"number", "history.list", `1`, false},
		{"bool", "history.list", `true`, false},
		{"trailing garbage", "history.list", `{"query":""}x`, false},
		{"trailing object", "history.list", `{"query":""} {}`, false},
		{"truncated", "history.list", `{"query":`, false},
		{"unknown field", "history.list", `{"query":"","extra":1}`, false},
		{"wrong type", "history.list", `{"query":1}`, false},
		{"nested unknown field", "registry.addEntry", `{"form":{"bogus":true}}`, false},
		{"fraction for int", "registry.updateEntry", `{"index":1.5}`, false},
		{"over limit", "history.list", long(maxParamsBytes + 1), false},
		{"at limit", "history.list", long(maxParamsBytes), true},
		{"empty", "history.list", ``, true},
		{"whitespace", "history.list", " \n\t", true},
		{"empty object", "history.list", `{}`, true},
		{"padded object", "history.list", " {\"query\":\"x\"} \n", true},
		{"no-param empty", "app.info", ``, true},
		{"no-param empty object", "app.info", `{}`, true},
		{"no-param unknown field", "app.info", `{"x":1}`, false},
		{"no-param null", "app.info", `null`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := h.call(t, tc.method, tc.params)
			if tc.wantOK {
				env.ok(t, nil)
				return
			}
			env.fails(t, CodeInput, msgBadParams)
		})
	}

	h.call(t, "no.such", `{}`).fails(t, CodeInput, msgUnknownMethod)
	h.call(t, "", ``).fails(t, CodeInput, msgUnknownMethod)
}

func TestDispatch_Envelopes(t *testing.T) {
	h := newHarness(t, nil)

	var info service.Info
	h.call(t, "app.info", ``).ok(t, &info)
	if !info.Online || info.ActiveKeys != 1 || info.Version == "" {
		t.Errorf("info = %+v", info)
	}
	if env := h.call(t, "bulk.cancel", ``); env.raw != `{"ok":true,"result":{}}` {
		t.Errorf("void envelope = %s", env.raw)
	}
	env := h.call(t, "sign.validate", `{}`)
	if env.raw != `{"ok":false,"error":{"code":"failed","message":"Recipient is required.","offerReport":false}}` {
		t.Errorf("error envelope = %s", env.raw)
	}
}

func TestDispatch_PanicIsInternal(t *testing.T) {
	h := newHarness(t, nil)
	const marker = "MARKER-PIN-123456"
	h.srv.methods["test.panic"] = func(*server, []byte) (any, error) { panic("value " + marker) }
	h.srv.methods["test.panicErr"] = func(*server, []byte) (any, error) { panic(errors.New(marker)) }
	h.srv.methods["test.badResult"] = func(*server, []byte) (any, error) { return make(chan int), nil }

	want := `{"ok":false,"error":{"code":"internal","message":"An internal error occurred — please restart","offerReport":false}}`
	for _, m := range []string{"test.panic", "test.panicErr", "test.badResult"} {
		if env := h.call(t, m, `{"pin":"`+marker+`"}`); env.raw != want {
			t.Errorf("%s: envelope = %s", m, env.raw)
		}
	}
	log := h.debugLog(t)
	for _, w := range []string{
		"rpc: panic in test.panic: string ",
		"rpc: panic in test.panicErr: *errors.errorString ",
		"rpc: panic in test.badResult: *json.UnsupportedTypeError ",
		"runtime/debug.Stack",
	} {
		if !strings.Contains(log, w) {
			t.Errorf("log lacks %q:\n%s", w, log)
		}
	}
	if strings.Contains(log, marker) {
		t.Errorf("log leaks the panic value or params:\n%s", log)
	}

	// The logged method name is sanitized and capped.
	name := "test.\u202epanic" + strings.Repeat("x", 100)
	h.srv.methods[name] = h.srv.methods["test.panic"]
	h.call(t, name, ``)
	logged := "rpc: panic in test. panic" + strings.Repeat("x", maxLogNameRunes-len("test. panic")) + ": string"
	if !strings.Contains(h.debugLog(t), logged) {
		t.Errorf("log lacks %q", logged)
	}
}

// msgLogUnreadable is Sign's message for an unreadable issuance log.
const msgLogUnreadable = "Could not read the issuance log, so duplicates can't be checked. Signing is blocked until it is readable."

func TestDispatch_ParamsNeverLogged(t *testing.T) {
	h := newHarness(t, nil)
	// An unreadable issuance log makes sign.sign fail after decoding its
	// params but before any card access.
	writeFile(t, filepath.Join(h.dir, "issuances.json"), "{corrupt")
	const marker = "MARKER-7f3a"
	for _, c := range []struct{ method, params string }{
		{"history.list", `{"query":"` + marker + `","x":1}`},
		{"history.list", `{"query":"` + marker + `"} trailing`},
		{"history.list", `{"query":` + jsonString(marker+strings.Repeat("a", maxParamsBytes)) + `}`},
		{"no.such." + marker, `{"a":"` + marker + `"}`},
		{"sign.validate", `{"recipient":"` + marker + `"}`},
		{"sign.sign", `{"recipient":"` + marker + `","honor":"Ennoblement","detail":"` + marker + `","date":"2026-01-02"}`},
		{"registry.addEntry", `{"form":{"authority":"` + marker + `"},"publicKey":"` + marker + `"}`},
		{"registry.updateEntry", `{"index":9,"publicKey":"` + marker + `","form":{"authority":"` + marker + `","from":"2026-01-01","noExpiry":true}}`},
	} {
		env := h.call(t, c.method, c.params)
		if env.OK {
			t.Fatalf("%s succeeded: %s", c.method, env.raw)
		}
		// sign.sign must stop at the unreadable log, never at a card.
		if c.method == "sign.sign" && env.Error.Message != msgLogUnreadable {
			t.Fatalf("sign.sign failed elsewhere: %s", env.raw)
		}
	}
	if log := h.debugLog(t); strings.Contains(log, marker) {
		t.Errorf("log contains params:\n%s", log)
	}
}

func TestSign(t *testing.T) {
	h := newHarness(t, ghapi.NewFakeKeyring())

	h.call(t, "sign.validate", validSign).ok(t, nil)
	h.call(t, "sign.validate", `{"recipient":"x","honor":"Ennoblement","detail":"d","date":"2026-02-30"}`).
		fails(t, CodeFailed, "Date must be in YYYY-MM-DD format and be a valid calendar date.")

	// A cancelled PIN prompt needs a card: see TestFakeSign_PINCancelled
	// (rhgfake build).

	// An unreadable issuance log fails before any PIN prompt or card access,
	// with a report offer.
	writeFile(t, filepath.Join(h.dir, "issuances.json"), "{corrupt")
	env := h.call(t, "sign.sign", validSign)
	env.fails(t, CodeFailed, "")
	if !env.Error.OfferReport || env.Error.ReportID != "1" {
		t.Fatalf("want a report offer with id 1: %s", env.raw)
	}

	var rep service.ReportResult
	h.call(t, "sign.reportError", `{"reportId":"1"}`).ok(t, &rep)
	if rep.Filed || !strings.HasPrefix(rep.URL, "https://github.com/") {
		t.Errorf("report = %+v", rep)
	}
	h.call(t, "sign.reportError", `{"reportId":"2"}`).fails(t, CodeNotFound, "This failure can no longer be reported.")
	h.call(t, "sign.reportError", ``).fails(t, CodeNotFound, "")

	var honors struct{ Honors []string }
	h.call(t, "sign.honors", ``).ok(t, &honors)
	if len(honors.Honors) == 0 || honors.Honors[len(honors.Honors)-1] != "Other" {
		t.Errorf("honors = %v", honors.Honors)
	}

	svg := filepath.Join(h.out, "qr.svg")
	h.call(t, "sign.saveQR", `{"url":"https://verify.example/?p=1","format":"svg","path":`+jsonString(svg)+`}`).ok(t, nil)
	if _, err := os.Stat(svg); err != nil {
		t.Errorf("QR not saved: %v", err)
	}
	h.call(t, "sign.saveQR", `{"url":"u","format":"bmp","path":`+jsonString(svg)+`}`).
		fails(t, CodeFailed, "Unsupported QR format.")
}

func TestSign_Existing(t *testing.T) {
	// A credential already in the log is rebuilt from it, with no PIN prompt
	// or card access.
	h := newHarness(t, nil)
	payload, err := core.BuildPayload(core.SignRequest{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"})
	if err != nil {
		t.Fatal(err)
	}
	rec := record(0, "Jane Doe")
	rec.PayloadSHA256 = core.PayloadSHA256Hex(payload)
	writeRecords(t, h.dir, []issuancelog.IssuanceRecord{rec})

	env := h.call(t, "sign.sign", validSign)
	var res service.SignResult
	env.ok(t, &res)
	if !res.Existing || res.Recipient != "Jane Doe" || res.Hash8 != rec.PayloadSHA256[:8] ||
		!strings.HasPrefix(string(res.PNGPreview), "\x89PNG") || res.SVGFilename == "" || res.PNGFilename == "" || res.URL == "" {
		t.Errorf("result = %+v", res)
	}
	for _, key := range []string{`"url":`, `"hash8":`, `"pngPreview":"`, `"svgFilename":`, `"pngFilename":`} {
		if !strings.Contains(string(env.Result), key) {
			t.Errorf("result lacks %s: %.200s", key, env.Result)
		}
	}
}

// TestSign_Offline: with no registry, sign.sign and bulk.run fail with
// CodeFailed and no report offer, before any PIN prompt; bulk.load still
// plans the file.
func TestSign_Offline(t *testing.T) {
	h := newOfflineHarness(t)
	for _, method := range []string{"sign.sign", "bulk.run"} {
		params := validSign
		if method == "bulk.run" {
			csv := filepath.Join(h.out, "in.csv")
			writeFile(t, csv, "name,honor,detail,date\nJane Doe,Ennoblement,For service,2026-01-02\n")
			var plan service.BulkPlan
			h.call(t, "bulk.load", `{"path":`+jsonString(csv)+`}`).ok(t, &plan)
			if plan.ToSign != 1 {
				t.Fatalf("offline plan = %+v", plan)
			}
			params = ``
		}
		env := h.call(t, method, params)
		env.fails(t, CodeFailed, service.ErrOffline.Error())
		if env.Error.OfferReport || env.Error.ReportID != "" {
			t.Errorf("%s offers a report: %s", method, env.raw)
		}
	}
	for _, e := range h.sink.all() {
		if strings.Contains(e, EventPINRequest) {
			t.Errorf("offline signing prompted: %s", e)
		}
	}
}

// TestBulk_LoadAndExport covers bulk without a card; a run waiting at the PIN
// prompt is TestFakeBulk_BusyAndCancel (rhgfake build).
func TestBulk_LoadAndExport(t *testing.T) {
	h := newHarness(t, nil)

	h.call(t, "bulk.run", ``).fails(t, CodeFailed, "No bulk file loaded.")
	h.call(t, "bulk.exportResults", `{"path":`+jsonString(filepath.Join(h.out, "r.csv"))+`}`).
		fails(t, CodeFailed, "No bulk file loaded.")
	h.call(t, "bulk.load", `{"path":`+jsonString(filepath.Join(h.out, "missing.csv"))+`}`).
		fails(t, CodeFailed, "Could not open the CSV file.")

	csv := filepath.Join(h.out, "in.csv")
	writeFile(t, csv, "name,honor,detail,date\nJane Doe,Ennoblement,For service,2026-01-02\nBob,Bogus,x,2026-01-02\n")
	var plan service.BulkPlan
	h.call(t, "bulk.load", `{"path":`+jsonString(csv)+`}`).ok(t, &plan)
	if plan.ToSign != 1 || len(plan.PreviewNames) != 1 || len(plan.InvalidLines) != 1 {
		t.Fatalf("plan = %+v", plan)
	}

	h.call(t, "bulk.cancel", ``).ok(t, nil) // nothing running: a no-op

	out := filepath.Join(h.out, "r.csv")
	h.call(t, "bulk.exportResults", `{"path":`+jsonString(out)+`}`).ok(t, nil)
	if _, err := os.Stat(out); err != nil {
		t.Errorf("results not saved: %v", err)
	}

	// Empty lists encode as [], not null.
	for _, c := range []struct{ rows, want string }{
		{"Jane Doe,Ennoblement,For service,2026-01-02\n", `"invalidLines":[]`},
		{"Bob,Bogus,x,2026-01-02\n", `"previewNames":[]`},
	} {
		writeFile(t, csv, "name,honor,detail,date\n"+c.rows)
		env := h.call(t, "bulk.load", `{"path":`+jsonString(csv)+`}`)
		env.ok(t, nil)
		if !strings.Contains(string(env.Result), c.want) {
			t.Errorf("result %s lacks %s", env.Result, c.want)
		}
	}
}

func TestAuth(t *testing.T) {
	h := newHarness(t, nil)
	if env := h.call(t, "auth.state", ``); string(env.Result) != `{"loggedIn":false,"offline":false,"user":"","statusText":"Not logged in"}` {
		t.Errorf("auth.state = %s", env.raw)
	}
	h.call(t, "auth.login", ``).fails(t, CodeLoginUnavailable, service.ErrLoginUnavailable.Error())
	h.call(t, "auth.cancelLogin", ``).ok(t, nil)
	h.call(t, "auth.logout", ``).ok(t, nil)

	want := `{"event":"auth.changed","data":{"loggedIn":false,"offline":false,"user":"","statusText":"Not logged in"}}`
	found := false
	for _, e := range h.sink.all() {
		found = found || e == want
	}
	if !found {
		t.Errorf("auth.changed %s not emitted; got %v", want, h.sink.all())
	}
}

func TestAuth_LoginFailsOffline(t *testing.T) {
	// With a keyring Login starts the device flow, which the dead proxy fails.
	h := newHarness(t, ghapi.NewFakeKeyring())
	h.call(t, "auth.login", ``).fails(t, CodeFailed, "")
}

// testCertPEM returns a self-signed Ed25519 certificate and its key as base64.
func testCertPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), base64.StdEncoding.EncodeToString(pub)
}

func TestRegistry(t *testing.T) {
	h := newHarness(t, nil)

	var snap service.RegistrySnapshot
	env := h.call(t, "registry.snapshot", ``)
	env.ok(t, &snap)
	if snap.Loaded || !strings.Contains(string(env.Result), `"entries":[]`) || !strings.Contains(string(env.Result), `"rows":[]`) {
		t.Errorf("unloaded snapshot = %s", env.Result)
	}
	h.call(t, "registry.addEntry", `{"form":{"authority":"X","from":"2026-01-01","noExpiry":true},"publicKey":"k"}`).
		fails(t, CodeFailed, service.ErrRegistryNotLoaded.Error())

	h.call(t, "registry.fetch", ``).ok(t, nil)
	h.call(t, "registry.snapshot", ``).ok(t, &snap)
	if !snap.Loaded || snap.Dirty || len(snap.Entries) != 1 || snap.Entries[0].PublicKey != testKeyB64(1) {
		t.Fatalf("snapshot = %+v", snap)
	}

	var cols struct{ Columns []string }
	h.call(t, "registry.columns", ``).ok(t, &cols)
	if len(cols.Columns) != len(snap.Rows[0]) || cols.Columns[1] != "Authority" {
		t.Errorf("columns = %v", cols.Columns)
	}

	certPath := filepath.Join(h.out, "key.pem")
	certPEM, certKey := testCertPEM(t)
	writeFile(t, certPath, string(certPEM))
	var key struct{ PublicKey string }
	h.call(t, "registry.importCertificate", `{"path":`+jsonString(certPath)+`}`).ok(t, &key)
	if key.PublicKey != certKey {
		t.Errorf("imported key = %q, want %q", key.PublicKey, certKey)
	}
	h.call(t, "registry.importCertificate", `{"path":`+jsonString(filepath.Join(h.out, "none.pem"))+`}`).fails(t, CodeFailed, "")

	h.call(t, "registry.addEntry", `{"form":{"authority":"New","from":"2026-01-01","noExpiry":true,"note":"n"},"publicKey":`+jsonString(certKey)+`}`).ok(t, nil)
	h.call(t, "registry.addEntry", `{"form":{"from":"2026-01-01"},"publicKey":"k"}`).fails(t, CodeFailed, "Authority is required.")
	h.call(t, "registry.updateEntry", `{"index":0,"publicKey":"stale","form":{"authority":"A2","from":"2026-01-01","noExpiry":true}}`).
		fails(t, CodeFailed, "The registry was reloaded while you were editing. Cancel and edit the entry again.")
	h.call(t, "registry.updateEntry", `{"index":0,"publicKey":`+jsonString(testKeyB64(1))+`,"form":{"authority":"A2","from":"2025-01-01","to":"2030-01-01"}}`).ok(t, nil)

	h.call(t, "registry.snapshot", ``).ok(t, &snap)
	if !snap.Dirty || len(snap.Entries) != 2 || snap.Entries[0].Authority != "A2" || snap.Entries[0].To != "2030-01-01" ||
		snap.Entries[1].Authority != "New" || !snap.Entries[1].NoExpiry {
		t.Errorf("edited snapshot = %+v", snap)
	}

	h.call(t, "registry.submit", ``).fails(t, CodeNotLoggedIn, service.ErrNotLoggedIn.Error())
}

func TestHistory(t *testing.T) {
	h := newHarness(t, nil)

	env := h.call(t, "history.list", `{"query":""}`)
	env.ok(t, nil)
	if !strings.Contains(string(env.Result), `"rows":[]`) {
		t.Errorf("empty history rows not []: %s", env.Result)
	}

	writeRecords(t, h.dir, []issuancelog.IssuanceRecord{record(1, "Alice Smith"), record(2, "Bob Jones"), record(2, "Bob Jones")})
	h.call(t, "history.refresh", ``).ok(t, nil)

	var snap service.HistorySnapshot
	h.call(t, "history.list", `{"query":"  ALICE "}`).ok(t, &snap)
	if len(snap.Rows) != 1 || snap.Rows[0].Record.Recipient != "Alice Smith" || !snap.RevocationsLoaded || snap.RevokeAvailable {
		t.Fatalf("snapshot = %+v", snap)
	}
	rec := snap.Rows[0].Record
	if rec.PayloadSHA256 != fmt.Sprintf("%064x", 1) {
		t.Errorf("record = %+v", rec)
	}

	recJSON, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recJSON), `"payloadSha256":`) || !strings.Contains(string(recJSON), `"signatureB64url":`) {
		t.Errorf("record JSON = %s", recJSON)
	}
	var text struct{ Detail, RevokeConfirm string }
	h.call(t, "history.recordText", `{"record":`+string(recJSON)+`}`).ok(t, &text)
	if text.Detail != service.FormatRecordDetail(rec) || text.RevokeConfirm != service.RevokeConfirmText(rec) {
		t.Errorf("text = %+v", text)
	}

	h.call(t, "history.revoke", `{"payloadSha256":`+jsonString(rec.PayloadSHA256)+`}`).
		fails(t, CodeNotLoggedIn, service.ErrNotLoggedIn.Error())

	var count struct{ Count int }
	h.call(t, "history.duplicatePreview", ``).ok(t, &count)
	if count.Count != 1 {
		t.Errorf("duplicates = %d", count.Count)
	}
	var removed struct {
		Removed int
		Backup  string
	}
	h.call(t, "history.removeDuplicates", ``).ok(t, &removed)
	if removed.Removed != 1 || removed.Backup == "" {
		t.Errorf("removed = %+v", removed)
	}

	export := filepath.Join(h.out, "log.json")
	h.call(t, "history.exportIssuanceLog", `{"path":`+jsonString(export)+`}`).ok(t, nil)
	if _, err := os.Stat(export); err != nil {
		t.Errorf("log not exported: %v", err)
	}
	h.call(t, "history.exportIssuanceLog", `{"path":"relative.json"}`).fails(t, CodeFailed, "Choose a file to save to.")

	writeFile(t, filepath.Join(h.dir, "issuances.json"), "{corrupt")
	h.call(t, "history.duplicatePreview", ``).fails(t, CodeFailed, "Could not read the issuance log.")
	h.call(t, "history.removeDuplicates", ``).fails(t, CodeFailed, "")
}

func TestAppExportErrorLog(t *testing.T) {
	h := newHarness(t, nil)
	out := filepath.Join(h.out, "debug.txt")
	h.call(t, "app.exportErrorLog", `{"path":`+jsonString(out)+`}`).ok(t, nil)
	if _, err := os.Stat(out); err != nil {
		t.Errorf("error log not exported: %v", err)
	}
	h.call(t, "app.exportErrorLog", `{"path":`+jsonString(filepath.Join(h.dir, "x.txt"))+`}`).
		fails(t, CodeFailed, service.ErrProtectedPath.Error())
}

func TestAuditCommits_Offline(t *testing.T) {
	h := newHarness(t, nil)
	h.call(t, "audit.commits", ``).fails(t, CodeFailed, "Failed to fetch registry history.")
}

// multiErr wraps several errors behind its own text, like service's userErr.
type multiErr struct {
	msg  string
	errs []error
}

func (e *multiErr) Error() string   { return e.msg }
func (e *multiErr) Unwrap() []error { return e.errs }

func TestClassify(t *testing.T) {
	if errBadParams.Error() != msgBadParams || errUnknownMethod.Error() != msgUnknownMethod {
		t.Error("input error texts differ from their messages")
	}
	cause := errors.New("cause")
	for _, tc := range []struct {
		name string
		err  error
		want errorInfo
	}{
		{"input", errBadParams, errorInfo{Code: CodeInput, Message: msgBadParams}},
		{"context canceled", context.Canceled, errorInfo{Code: CodeCancelled, Message: "context canceled"}},
		{"login cancelled", &multiErr{"Login cancelled.", []error{context.Canceled}}, errorInfo{Code: CodeCancelled, Message: "Login cancelled."}},
		{"sign cancel", &multiErr{"Signing cancelled.", []error{context.Canceled, cause}}, errorInfo{Code: CodeCancelled, Message: "Signing cancelled."}},
		{"nothing to export", &multiErr{"Nothing yet.", []error{service.ErrNothingToExport}}, errorInfo{Code: CodeNothingToExport, Message: "Nothing yet."}},
		{"login unavailable", service.ErrLoginUnavailable, errorInfo{Code: CodeLoginUnavailable, Message: service.ErrLoginUnavailable.Error()}},
		{"busy", service.ErrBusy, errorInfo{Code: CodeBusy, Message: service.ErrBusy.Error()}},
		{"wrapped busy", fmt.Errorf("x: %w", service.ErrBusy), errorInfo{Code: CodeBusy, Message: "x: " + service.ErrBusy.Error()}},
		{"not logged in", service.ErrNotLoggedIn, errorInfo{Code: CodeNotLoggedIn, Message: service.ErrNotLoggedIn.Error()}},
		{"session expired", &multiErr{"Log in again.", []error{service.ErrSessionExpired, cause}}, errorInfo{Code: CodeSessionExpired, Message: "Log in again."}},
		{"session expired joined", errors.Join(cause, service.ErrSessionExpired), errorInfo{Code: CodeSessionExpired, Message: "cause\n" + service.ErrSessionExpired.Error()}},
		{"registry changed", service.ErrRegistryChanged, errorInfo{Code: CodeRegistryChanged, Message: service.ErrRegistryChanged.Error()}},
		{"not found", &multiErr{"Gone.", []error{service.ErrNotFound}}, errorInfo{Code: CodeNotFound, Message: "Gone."}},
		{"failed", cause, errorInfo{Code: CodeFailed, Message: "cause"}},
		{"sign failed", &service.SignError{Message: "Bad.", Err: cause}, errorInfo{Code: CodeFailed, Message: "Bad."}},
		{"sign failed reportable", &service.SignError{Message: "Bad.", OfferReport: true, ReportID: "7", Err: cause}, errorInfo{Code: CodeFailed, Message: "Bad.", OfferReport: true, ReportID: "7"}},
		{"sign error wrapping busy", &service.SignError{Message: "Busy.", Err: service.ErrBusy}, errorInfo{Code: CodeBusy, Message: "Busy."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err); got != tc.want {
				t.Errorf("classify = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDispatch_NilLogger(t *testing.T) {
	s := &server{state: stateReady, methods: map[string]handler{"p": func(*server, []byte) (any, error) { panic(1) }}}
	dispatch(t, s, "p", ``).fails(t, CodeInternal, msgInternal)
}
