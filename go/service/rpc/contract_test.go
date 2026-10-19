package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/buildinfo"
	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

// updateContract makes TestContract rewrite the contract files instead of
// comparing them.
var updateContract = flag.Bool("update", false, "rewrite testdata/contract from the current Dispatch and event output")

const (
	contractDir    = "testdata/contract"
	regenerateHint = "regenerate from go/ with: go test ./service/rpc -run TestContract -update"
	repoURL        = "https://github.com/RoyalHouseOfGeorgia/rhg_authenticator"
	// pngPlaceholder is base64 of the 8-byte PNG signature.
	pngPlaceholder = "iVBORw0KGgo="
	registryOrigin = "https://registry.example"
)

// contractParamTypes is each method's params type, as its handler decodes it.
var contractParamTypes = map[string]any{
	"app.init":                   initParams{},
	"app.start":                  struct{}{},
	"app.canQuit":                struct{}{},
	"app.shutdown":               shutdownParams{},
	"app.info":                   struct{}{},
	"app.exportErrorLog":         pathParams{},
	"sign.honors":                struct{}{},
	"sign.validate":              service.SignFields{},
	"sign.sign":                  service.SignFields{},
	"sign.saveQR":                saveQRParams{},
	"sign.reportError":           reportParams{},
	"bulk.load":                  pathParams{},
	"bulk.run":                   struct{}{},
	"bulk.cancel":                struct{}{},
	"bulk.exportResults":         pathParams{},
	"yubikey.check":              struct{}{},
	"auth.state":                 struct{}{},
	"auth.login":                 struct{}{},
	"auth.cancelLogin":           struct{}{},
	"auth.logout":                struct{}{},
	"registry.snapshot":          struct{}{},
	"registry.columns":           struct{}{},
	"registry.fetch":             struct{}{},
	"registry.addEntry":          addEntryParams{},
	"registry.updateEntry":       updateEntryParams{},
	"registry.importCertificate": pathParams{},
	"registry.importFromYubiKey": struct{}{},
	"registry.submit":            struct{}{},
	"history.refresh":            struct{}{},
	"history.list":               queryParams{},
	"history.recordText":         recordParams{},
	"history.revoke":             revokeParams{},
	"history.exportIssuanceLog":  pathParams{},
	"history.duplicatePreview":   struct{}{},
	"history.removeDuplicates":   struct{}{},
	"pin.submit":                 pinSubmitParams{},
	"pin.cancel":                 pinCancelParams{},
	"update.current":             struct{}{},
	"audit.commits":              struct{}{},
}

// scrubber replaces the values that differ between runs and machines.
type scrubber struct {
	prefixes []prefixRule
}

// prefixRule replaces from, when it is a whole leading path or URL segment,
// with to.
type prefixRule struct{ from, to string }

// clockRules fix the timestamps the service takes from the clock.
var clockRules = []struct {
	re    *regexp.Regexp
	fixed string
}{
	{regexp.MustCompile(`rhg-bulk-results-\d{4}-\d{2}-\d{2}-\d{6}\.csv`), "rhg-bulk-results-2026-01-02-030405.csv"},
	{regexp.MustCompile(`\.bak-\d{8}T\d{6}Z`), ".bak-20260102T030405Z"},
}

// scrubDocs lists every scrub rule for the README.
var scrubDocs = []string{
	"Paths under the test's temporary directories: the app data directory becomes `/DATA` and the folder files are saved to becomes `/OUT`, with `/` separators.",
	"The local test registry server's origin (`http://127.0.0.1:<port>`) becomes `" + registryOrigin + "`.",
	"Every `pngPreview` value becomes `" + pngPlaceholder + "` (base64 of the PNG signature).",
	"The clock time in a bulk results file name becomes `rhg-bulk-results-2026-01-02-030405.csv`, and in an issuance-log backup name `.bak-20260102T030405Z`.",
}

// addDir maps dir, and its symlink-resolved form, to placeholder.
func (s *scrubber) addDir(dir, placeholder string) {
	s.add(dir, placeholder)
	if real, err := filepath.EvalSymlinks(dir); err == nil && real != dir {
		s.add(real, placeholder)
	}
}

func (s *scrubber) add(from, to string) {
	s.prefixes = append(s.prefixes, prefixRule{from, to})
	sort.SliceStable(s.prefixes, func(i, j int) bool { return len(s.prefixes[i].from) > len(s.prefixes[j].from) })
}

// value scrubs v, a decoded JSON value found under key, in place.
func (s *scrubber) value(key string, v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = s.value(k, e)
		}
	case []any:
		for i, e := range v {
			v[i] = s.value(key, e)
		}
	case string:
		if key == "pngPreview" {
			return pngPlaceholder
		}
		return s.str(v)
	}
	return v
}

func (s *scrubber) str(v string) string {
	for _, p := range s.prefixes {
		if rest, ok := strings.CutPrefix(v, p.from); ok && (rest == "" || rest[0] == '/' || rest[0] == '\\') {
			v = p.to + filepath.ToSlash(rest)
			break
		}
	}
	for _, r := range clockRules {
		v = r.re.ReplaceAllString(v, r.fixed)
	}
	return v
}

// canonical decodes raw (a single JSON value), scrubs it and re-encodes it
// canonically.
func (s *scrubber) canonical(t testing.TB, raw []byte) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%s does not decode: %v", raw, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("%s has trailing data", raw)
	}
	return encodeCanonical(t, s.value("", v))
}

// encodeCanonical encodes v compactly with sorted keys, no HTML escaping and
// a trailing newline.
func encodeCanonical(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// contract collects the contract files, keyed by slash path.
type contract struct {
	t     *testing.T
	scrub scrubber
	files map[string][]byte
	kinds map[string]string // method → "dispatch" or "encoded"
}

func (c *contract) add(name string, raw []byte) {
	c.t.Helper()
	if _, dup := c.files[name]; dup {
		c.t.Fatalf("contract file %s generated twice", name)
	}
	c.files[name] = c.scrub.canonical(c.t, raw)
}

// method records a method's params and success envelope.
func (c *contract) method(name string, params, envelope []byte, kind string) {
	c.t.Helper()
	if !bytes.HasPrefix(envelope, []byte(`{"ok":true,`)) {
		c.t.Fatalf("%s did not succeed: %s", name, envelope)
	}
	c.kinds[name] = kind
	c.add("methods/"+name+"/params.json", params)
	c.add("methods/"+name+"/result.json", envelope)
}

// dispatch calls method on s with params p and records it.
func (c *contract) dispatch(s *server, name string, p any) []byte {
	c.t.Helper()
	params := mustMarshal(p)
	out := s.Dispatch(name, params)
	c.method(name, params, out, "dispatch")
	return out
}

// encoded records a method whose success needs hardware or GitHub: result
// goes through Dispatch's success encoder.
func (c *contract) encoded(name string, p, result any) {
	c.t.Helper()
	c.method(name, mustMarshal(p), mustMarshal(successBody{OK: true, Result: result}), "encoded")
}

// variant records another success result of method, one per value of an
// enum clients decode, as methods/<method>/result.<value>.json, through the
// success encoder.
func (c *contract) variant(method, value string, result any) {
	c.t.Helper()
	c.add("methods/"+method+"/result."+value+".json", mustMarshal(successBody{OK: true, Result: result}))
}

func (c *contract) errorFile(name string, envelope []byte) {
	c.t.Helper()
	if !bytes.HasPrefix(envelope, []byte(`{"ok":false,`)) {
		c.t.Fatalf("error %s: envelope %s", name, envelope)
	}
	c.add("errors/"+name+".json", envelope)
}

func (c *contract) event(name string, raw []byte) {
	c.t.Helper()
	c.add("events/"+name+".json", raw)
}

// lastRaw returns the last recorded event called name.
func lastRaw(t testing.TB, s *eventSink, name string) []byte {
	t.Helper()
	all := s.all()
	for i := len(all) - 1; i >= 0; i-- {
		var ev struct{ Event string }
		if err := json.Unmarshal([]byte(all[i]), &ev); err == nil && ev.Event == name {
			return []byte(all[i])
		}
	}
	t.Fatalf("no %s event in %v", name, all)
	return nil
}

func waitFor[T any](t testing.TB, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitTimeout):
		t.Fatalf("%s never happened", what)
		var zero T
		return zero
	}
}

// seededCertPEM returns a self-signed certificate for a fixed Ed25519 key and
// that key as base64.
func seededCertPEM(t testing.TB) ([]byte, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), base64.StdEncoding.EncodeToString(pub)
}

// buildContract generates every contract file.
func buildContract(t *testing.T) *contract {
	c := &contract{t: t, files: map[string][]byte{}, kinds: map[string]string{}}
	c.files[".gitattributes"] = []byte("* -text\n")
	bg := context.Background()
	empty := struct{}{}

	// The issuance log: Alice (revoked), Jane (the credential validSign
	// reuses) and a duplicated Bob, oldest first.
	payload, err := core.BuildPayload(core.SignRequest{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"})
	if err != nil {
		t.Fatal(err)
	}
	alice := record(1, "Alice Smith")
	jane := record(0, "Jane Doe")
	jane.Timestamp, jane.PayloadSHA256 = "2026-02-03T04:05:06Z", core.PayloadSHA256Hex(payload)
	bob := record(2, "Bob Jones")
	bob.Timestamp, bob.Date = "2026-03-04T05:06:07Z", "2026-03-04"
	revocations := `{"revocations":[{"hash":"` + alice.PayloadSHA256 + `","revoked_on":"2026-03-01"}]}`

	h := newHarnessWith(t, nil, revocations)
	c.scrub.addDir(h.dir, "/DATA")
	c.scrub.addDir(h.out, "/OUT")
	srvSink := newEventSink()
	h.srv.events.SetSink(srvSink.add)

	c.dispatch(h.srv, "registry.fetch", empty)
	writeRecords(t, h.dir, []issuancelog.IssuanceRecord{alice, jane, bob, bob})
	c.dispatch(h.srv, "history.refresh", empty)
	c.dispatch(h.srv, "history.list", queryParams{Query: ""})
	c.dispatch(h.srv, "history.recordText", recordParams{Record: service.HistoryRecord{
		Timestamp: alice.Timestamp, Recipient: alice.Recipient, Honor: alice.Honor, Detail: alice.Detail,
		Date: alice.Date, PayloadSHA256: alice.PayloadSHA256, SignatureB64URL: alice.SignatureB64URL,
	}})
	c.dispatch(h.srv, "history.duplicatePreview", empty)
	c.dispatch(h.srv, "history.removeDuplicates", empty)
	c.dispatch(h.srv, "history.exportIssuanceLog", pathParams{Path: filepath.Join(h.out, "issuances-export.json")})

	sign := service.SignFields{Recipient: "Jane Doe", Honor: "Ennoblement", Detail: "For service", Date: "2026-01-02"}
	c.dispatch(h.srv, "sign.validate", sign)
	var signed struct{ Result service.SignResult }
	if err := json.Unmarshal(c.dispatch(h.srv, "sign.sign", sign), &signed); err != nil || !signed.Result.Existing {
		t.Fatalf("sign.sign = %+v, %v", signed, err)
	}
	c.dispatch(h.srv, "sign.saveQR", saveQRParams{URL: signed.Result.URL, Format: "svg", Path: filepath.Join(h.out, signed.Result.SVGFilename)})
	c.dispatch(h.srv, "sign.honors", empty)
	c.dispatch(h.srv, "app.info", empty)
	c.dispatch(h.srv, "app.exportErrorLog", pathParams{Path: filepath.Join(h.out, "error-log.txt")})

	// Errors reachable without a card or GitHub. A cancelled PIN prompt
	// needs a card (the key is read first), so cancelled goes through the
	// error encoder.
	c.errorFile(CodeCancelled, errorEnvelope(signCancelled{}))
	c.errorFile(CodeFailed, h.srv.Dispatch("sign.validate", []byte(`{}`)))
	c.errorFile(CodeNotFound, h.srv.Dispatch("sign.reportError", mustMarshal(reportParams{ReportID: "1"})))
	c.errorFile(CodeNotLoggedIn, h.srv.Dispatch("registry.submit", nil))
	c.errorFile(CodeInput, h.srv.Dispatch("no.such", []byte(`{}`)))
	h.srv.methods["contract.panic"] = func(*server, []byte) (any, error) { panic("contract") }
	c.errorFile(CodeInternal, h.srv.Dispatch("contract.panic", nil))
	delete(h.srv.methods, "contract.panic")

	// Bulk. Signing a row needs a card, so the run is of a file with nothing
	// to sign (already issued and invalid rows); busy, which needs a run
	// holding the card, goes through the error encoder.
	csv := filepath.Join(h.out, "bulk.csv")
	writeFile(t, csv, "name,honor,detail,date\nJane Doe,Ennoblement,For service,2026-01-02\nCarol White,Ennoblement,For service,2026-01-05\nBob,Bogus,x,2026-01-02\n")
	c.dispatch(h.srv, "bulk.load", pathParams{Path: csv})
	c.errorFile(CodeBusy, errorEnvelope(service.ErrBusy))
	writeFile(t, csv, "name,honor,detail,date\nJane Doe,Ennoblement,For service,2026-01-02\nBob,Bogus,x,2026-01-02\n")
	if env := h.srv.Dispatch("bulk.load", mustMarshal(pathParams{Path: csv})); !bytes.Contains(env, []byte(`"toSign":0`)) {
		t.Fatalf("bulk.load of the nothing-to-sign file = %s", env)
	}
	// This bulk.run is of the second, nothing-to-sign load above, not of the
	// recorded bulk.load plan. A run that stops early needs a card, so those
	// outcomes go through the success encoder, one file per stopped value.
	c.dispatch(h.srv, "bulk.run", empty)
	for _, o := range []service.BulkOutcome{
		{Stopped: service.BulkCancelled, StopMessage: "Cancelled.", FailedLines: []string{},
			SummaryLine: "Processed 3 rows: 1 successful (1 newly signed, 0 already issued), 0 invalid, 2 failed/not attempted."},
		{Stopped: service.BulkFailed, StopMessage: "Batch stopped: Incorrect PIN — 2 attempt(s) left before the YubiKey locks.",
			FailedLines: []string{"line 2: Incorrect PIN — 2 attempt(s) left before the YubiKey locks."},
			SummaryLine: "Processed 3 rows: 0 successful (0 newly signed, 0 already issued), 0 invalid, 3 failed/not attempted."},
	} {
		o.ResultsFilename = "rhg-bulk-results-2026-01-02-030405.csv"
		c.variant("bulk.run", string(o.Stopped), o)
	}
	c.dispatch(h.srv, "bulk.cancel", empty)
	c.dispatch(h.srv, "bulk.exportResults", pathParams{Path: filepath.Join(h.out, "bulk-results.csv")})

	c.dispatch(h.srv, "auth.state", empty)
	c.dispatch(h.srv, "auth.cancelLogin", empty)
	c.dispatch(h.srv, "auth.logout", empty)

	certPath := filepath.Join(h.out, "certificate.pem")
	certPEM, certKey := seededCertPEM(t)
	writeFile(t, certPath, string(certPEM))
	c.dispatch(h.srv, "registry.columns", empty)
	c.dispatch(h.srv, "registry.importCertificate", pathParams{Path: certPath})
	c.dispatch(h.srv, "registry.addEntry", addEntryParams{
		Form:      service.EntryForm{Authority: "New Authority", From: "2026-01-01", Note: "Second key", NoExpiry: true},
		PublicKey: certKey,
	})
	c.dispatch(h.srv, "registry.updateEntry", updateEntryParams{
		Index:     0,
		PublicKey: testKeyB64(1),
		Form:      service.EntryForm{Authority: "A", From: "2025-01-01", To: "2030-12-31"},
	})
	c.dispatch(h.srv, "registry.snapshot", empty)
	c.dispatch(h.srv, "app.canQuit", empty)

	// Update offers through the update manager's callbacks.
	const release = repoURL + "/releases/tag/v9.9.9"
	for _, st := range []update.Status{
		{State: update.StateIdle},
		{State: update.StateManualOnly, Version: "9.9.9", ReleaseURL: release, MoveToApplications: true},
		{State: update.StateReady, Version: "9.9.9", ReleaseURL: release},
	} {
		h.srv.onUpdateStatus(st)
		c.event(EventUpdateStatus+"."+statusJSON(st).State, lastRaw(t, srvSink, EventUpdateStatus))
	}
	h.srv.events.SetSink(nil)
	h.srv.onUpdated("9.9.8", repoURL+"/releases/tag/v9.9.8")
	h.srv.events.SetSink(srvSink.add)
	c.dispatch(h.srv, "update.current", empty)
	h.srv.onUpdated("9.9.8", repoURL+"/releases/tag/v9.9.8")
	c.event(EventUpdateUpdated, lastRaw(t, srvSink, EventUpdateUpdated))

	// The PIN bridge, prompted directly as the service's Prompter would.
	request := func(ctx context.Context, rememberDefault bool, n int) <-chan pinOutcome {
		out := make(chan pinOutcome, 1)
		go func() {
			pin, remember, err := h.srv.pins.RequestPIN(ctx, rememberDefault)
			out <- pinOutcome{pin, remember, err}
		}()
		srvSink.wait(t, EventPINRequest, n)
		return out
	}
	out := request(bg, true, 1)
	c.event(EventPINRequest, lastRaw(t, srvSink, EventPINRequest))
	c.dispatch(h.srv, "pin.submit", pinSubmitParams{RequestID: 1, PIN: "123456", Remember: true})
	receive(t, out)
	out = request(bg, false, 2)
	c.dispatch(h.srv, "pin.cancel", pinCancelParams{RequestID: 2})
	receive(t, out)
	ctx, cancel := context.WithCancel(bg)
	out = request(ctx, false, 3)
	cancel()
	receive(t, out)
	srvSink.wait(t, EventPINDismiss, 1)
	c.event(EventPINDismiss, lastRaw(t, srvSink, EventPINDismiss))

	kh := newHarness(t, ghapi.NewFakeKeyring())
	c.scrub.addDir(kh.dir, "/DATA")
	c.errorFile(CodeNothingToExport, kh.srv.Dispatch("history.exportIssuanceLog", mustMarshal(pathParams{Path: filepath.Join(kh.out, "empty.json")})))
	c.errorFile(CodeLoginUnavailable, h.srv.Dispatch("auth.login", nil))
	writeFile(t, filepath.Join(kh.dir, "issuances.json"), "{corrupt")
	c.errorFile("failed-with-report", kh.srv.Dispatch("sign.sign", mustMarshal(sign)))
	c.errorFile(CodeSessionExpired, errorEnvelope(service.ErrSessionExpired))
	c.errorFile(CodeRegistryChanged, errorEnvelope(service.ErrRegistryChanged))

	// The lifecycle, against a local registry.
	lc := newLC(t)
	dataDir := filepath.Join(lc.tmp, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c.scrub.addDir(dataDir, "/DATA")
	c.scrub.add(lc.reg.URL, registryOrigin)
	c.dispatch(lc.srv, "app.init", initParams{DataDir: dataDir})
	c.dispatch(lc.srv, "app.start", empty)
	for _, e := range []string{service.EventRegistryChanged, service.EventHistoryChanged, service.EventRevocationsChanged} {
		lc.sink.wait(t, e, 1)
	}
	waitFor(t, lc.mgr.running, "the update manager running")
	c.dispatch(lc.srv, "app.shutdown", shutdownParams{Relaunch: false})

	// Methods whose success needs a YubiKey or GitHub.
	key, err := base64.StdEncoding.DecodeString(testKeyB64(1))
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(key)
	c.encoded("yubikey.check", empty, service.KeyCheck{
		Outcome: service.KeyCheckFound,
		Status:  "Key found in registry",
		Details: []string{
			"Authority: A",
			"Valid from: 2025-Jan-01",
			"Valid to: (no expiry)",
			"Restrictions: (none)",
			"Fingerprint: " + hex.EncodeToString(fp[:]),
		},
	})
	c.variant("yubikey.check", string(service.KeyCheckNotFound), service.KeyCheck{
		Outcome: service.KeyCheckNotFound,
		Status:  "Key NOT found in registry",
		Details: []string{"Fingerprint: " + hex.EncodeToString(fp[:])},
	})
	// Offline the check fails without reading a card, so this one is real.
	c.add("methods/yubikey.check/result."+string(service.KeyCheckFailed)+".json",
		newOfflineHarness(t).srv.Dispatch("yubikey.check", nil))
	c.encoded("registry.importFromYubiKey", empty, publicKeyResult{PublicKey: testKeyB64(1)})
	c.encoded("auth.login", empty, service.AuthState{LoggedIn: true, User: "octocat"})
	c.encoded("registry.submit", empty, service.SubmitResult{PRNumber: 42, URL: repoURL + "/pull/42"})
	c.encoded("history.revoke", revokeParams{PayloadSHA256: bob.PayloadSHA256}, service.RevokeResult{
		Status:   service.RevokeSubmitted,
		PRNumber: 43,
		URL:      repoURL + "/pull/43",
		Title:    "Revocation Submitted",
		Message:  "Pull request #43 created:\n" + repoURL + "/pull/43\n\nIf several revocation PRs are open, merge them one at a time.",
	})
	c.variant("history.revoke", string(service.RevokeAlreadyRevoked), service.RevokeResult{
		Status: service.RevokeAlreadyRevoked, Title: "Already Revoked", Message: ghapi.UserMessage(ghapi.ErrAlreadyRevoked),
	})
	c.variant("history.revoke", string(service.RevokePending), service.RevokeResult{
		Status: service.RevokePending, Title: "Revocation Pending", Message: ghapi.UserMessage(ghapi.ErrRevocationPending),
	})
	c.encoded("audit.commits", empty, service.AuditResult{
		Rows: []service.AuditRow{{
			Summary: "2026-Jan-02  Jane Doe — Add key for A",
			URL:     repoURL + "/commit/" + strings.Repeat("0123456789", 4),
		}},
		Status: "Loaded 1 commits",
	})
	c.encoded("sign.reportError", reportParams{ReportID: "1"}, service.ReportResult{URL: repoURL + "/issues/44", Filed: true})

	// Service events, with representative payloads.
	ev := newJSONEvents(nil)
	rec := &sinkRecorder{}
	ev.SetSink(rec.add)
	for _, e := range []struct {
		name    string
		payload any
	}{
		{service.EventSignConnecting, nil},
		{service.EventBulkConnecting, nil},
		{service.EventBulkProgress, service.BulkProgress{Done: 1, Total: 3, Name: "Jane Doe"}},
		{service.EventAuthChanged, service.AuthState{LoggedIn: true, User: "octocat"}},
		{service.EventAuthDeviceCode, service.DeviceCode{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"}},
		{service.EventRegistryChanged, nil},
		{service.EventHistoryChanged, nil},
		{service.EventRevocationsChanged, nil},
		{EventInternalError, nil},
	} {
		ev.Emit(e.name, e.payload)
		all := rec.all()
		c.event(e.name, []byte(all[len(all)-1]))
	}

	c.add("pin-truncation.json", mustMarshal(pinTruncationCases()))
	c.add("methods/index.json", mustMarshal(c.kinds))
	c.files["README.md"] = []byte(contractReadme(c.kinds))
	return c
}

// signCancelled stands in for Sign's cancelled-PIN error: the cancel text,
// matching context.Canceled.
type signCancelled struct{}

func (signCancelled) Error() string { return "Signing cancelled." }
func (signCancelled) Unwrap() error { return context.Canceled }

type truncationCase struct {
	Input    string `json:"input"`
	MaxBytes int    `json:"maxBytes"`
	Output   string `json:"output"`
}

// pinTruncationCases runs service.TruncatePINToBytes over inputs that tell
// UTF-8 bytes apart from UTF-16 units and grapheme clusters.
func pinTruncationCases() []truncationCase {
	in := []struct {
		s   string
		max int
	}{
		{"", 8},
		{"1234", 8},
		{"12345678", 8},
		{"123456789", 8},
		{"აბგ", 8},      // 3-byte letters: 9 bytes
		{"1234567ა", 8}, // the last letter crosses the limit
		{"12345é", 8},  // e + combining acute: exactly 8 bytes
		{"123456é", 8}, // the combining mark crosses the limit
		{"1234😀", 8},    // 4-byte (UTF-16 surrogate pair): exactly 8 bytes
		{"12345😀", 8},   // the emoji crosses the limit
		{"აბგ", 4},
		{"123456", 0},
		{"😀😀😀😀😀", 16},
	}
	out := make([]truncationCase, len(in))
	for i, c := range in {
		out[i] = truncationCase{Input: c.s, MaxBytes: c.max, Output: service.TruncatePINToBytes(c.s, c.max)}
	}
	return out
}

func contractReadme(kinds map[string]string) string {
	var encoded []string
	for m, k := range kinds {
		if k == "encoded" {
			encoded = append(encoded, "`"+m+"`")
		}
	}
	slices.Sort(encoded)
	var b strings.Builder
	b.WriteString(`# RPC contract

Generated by TestContract (go/service/rpc/contract_test.go) from real
Dispatch and jsonEvents.Emit output; do not edit by hand. Regenerate from go/:

    go test ./service/rpc -run TestContract -update

Without -update the test fails on any missing, extra or changed file.

## Layout

- methods/<method>/params.json: a representative params object ({} for a
  method without params). It decodes with the Go decoder, which rejects
  unknown fields, and re-encodes to the same bytes, so it holds every field.
- methods/<method>/result.json: the full success envelope,
  {"ok":true,"result":...}.
- methods/index.json: how each result was produced. "dispatch": a real
  Dispatch call against a local test registry. "encoded": success needs a
  YubiKey or GitHub, so a representative value of the method's real result
  type went through Dispatch's success encoder. Encoded: ` + strings.Join(encoded, ", ") + `.
- errors/<code>.json: one error envelope per error code.
  errors/failed-with-report.json is a "failed" error offering a report
  (offerReport true, with reportId); reportId is absent otherwise. busy,
  cancelled, sessionExpired and registryChanged need a card or GitHub, so
  their files went through Dispatch's error encoder.
- events/<event>.json: one event, {"event":...,"data":...}, as delivered to
  the event callback. update.status has one file per state:
  events/update.status.<state>.json.
- methods/<method>/result.<value>.json: for a result enum clients decode
  (bulk.run stopped, yubikey.check result, history.revoke status), result.json
  holds the first value and one file per other value holds the rest, through
  the success encoder. bulk.run/result.json is a run of a second,
  nothing-to-sign load, not of the recorded bulk.load plan.
- pin-truncation.json: [{"input","maxBytes","output"}] cases from
  service.TruncatePINToBytes. Clients cap a PIN to maxBytes bytes of its
  UTF-8 encoding, cutting only between Unicode scalar values; never count
  UTF-16 code units or grapheme clusters (a combining mark or an emoji may
  be cut off).

## What clients may branch on

Clients branch only on ok, the error code and offerReport, and on typed
fields: booleans, enums (update state, bulk stopped, key-check result, revoke
status), numbers and ids. CodeFailed means "show the message"; "input" always
means a host programming error.

Display strings are render-only and may change in any release: never compare
or parse them. They are every message, statusText, summary, summaryLine,
countsLine, stopMessage, title, the key-check status and details, the
registry rows and columns, recordText's detail and revokeConfirm, and every
*Filename.

## Canonical encoding

Each file is its JSON value re-encoded as: compact (no whitespace between
tokens); object keys sorted by byte order (ordinal, not locale); UTF-8 with
non-ASCII characters unescaped; "/", "<", ">" and "&" not escaped; numbers
as produced; a single trailing "\n". A client's encoder output for each
params file must equal the file under these rules (Swift: JSONEncoder with
.sortedKeys and .withoutEscapingSlashes; C#: a writer that orders keys
ordinally and escapes neither non-ASCII nor "/").

## Scrubbed values

Inputs are fixed (fixture dates and records, a seeded certificate key);
then only these values are replaced:

`)
	for _, d := range scrubDocs {
		b.WriteString("- " + d + "\n")
	}
	b.WriteString(`
The app version is the unstamped "dev" of test builds.

.gitattributes marks every file -text so checkouts keep LF line endings.
`)
	return b.String()
}

// constValues returns the values of the string constants whose names start
// with prefix in the non-test Go files of dirs.
func constValues(t *testing.T, prefix string, dirs ...string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if !strings.HasPrefix(name.Name, prefix) {
							continue
						}
						if i >= len(vs.Values) {
							t.Fatalf("%s: %s has no explicit value", e.Name(), name.Name)
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							t.Fatalf("%s: %s is not a string literal", e.Name(), name.Name)
						}
						v, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatal(err)
						}
						out[v] = true
					}
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s* constants in %v", prefix, dirs)
	}
	return out
}

// checkCompleteness fails unless every method, event and error code has its
// contract files and no file is for an unknown one.
func checkCompleteness(t *testing.T, c *contract) {
	table := methodTable()
	for name := range table {
		if c.kinds[name] == "" {
			t.Errorf("method %s has no contract files", name)
		}
		if _, ok := contractParamTypes[name]; !ok {
			t.Errorf("method %s has no entry in contractParamTypes", name)
		}
	}
	for name := range c.kinds {
		if table[name] == nil {
			t.Errorf("contract files for unknown method %s", name)
		}
	}
	for name := range contractParamTypes {
		if table[name] == nil {
			t.Errorf("contractParamTypes has unknown method %s", name)
		}
	}

	events := constValues(t, "Event", "..", ".")
	codes := constValues(t, "Code", ".")
	seen := map[string]bool{}
	for name, data := range c.files {
		dir := path.Dir(name)
		switch dir {
		case "events":
			var ev struct{ Event string }
			if err := json.Unmarshal(data, &ev); err != nil || !events[ev.Event] {
				t.Errorf("%s is for unknown event %q", name, ev.Event)
			}
			seen[ev.Event] = true
		case "errors":
			var env struct{ Error struct{ Code string } }
			if err := json.Unmarshal(data, &env); err != nil || !codes[env.Error.Code] {
				t.Errorf("%s has unknown code %q", name, env.Error.Code)
			}
		}
	}
	for e := range events {
		if !seen[e] {
			t.Errorf("event %s has no events file", e)
		}
	}
	for code := range codes {
		if c.files["errors/"+code+".json"] == nil {
			t.Errorf("error code %s has no errors/%s.json", code, code)
		}
	}
	// Every value of a result enum clients decode has an example: the first
	// in result.json, the others in result.<value>.json.
	for _, e := range []struct {
		method, field string
		values        []string
	}{
		{"bulk.run", "stopped", []string{string(service.BulkCompleted), string(service.BulkCancelled), string(service.BulkFailed)}},
		{"yubikey.check", "outcome", []string{string(service.KeyCheckFound), string(service.KeyCheckNotFound), string(service.KeyCheckFailed)}},
		{"history.revoke", "status", []string{string(service.RevokeSubmitted), string(service.RevokeAlreadyRevoked), string(service.RevokePending)}},
	} {
		dir := "methods/" + e.method + "/"
		if !bytes.Contains(c.files[dir+"result.json"], []byte(`"`+e.field+`":"`+e.values[0]+`"`)) {
			t.Errorf("%sresult.json is not %s %q", dir, e.field, e.values[0])
		}
		for _, v := range e.values[1:] {
			if !bytes.Contains(c.files[dir+"result."+v+".json"], []byte(`"`+e.field+`":"`+v+`"`)) {
				t.Errorf("%s %s %q has no example", e.method, e.field, v)
			}
		}
	}
}

// readContract returns the files under contractDir, keyed by slash path.
func readContract(t *testing.T) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	err := filepath.WalkDir(contractDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(contractDir, p)
		got[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatalf("reading %s: %v; %s", contractDir, err, regenerateHint)
	}
	return got
}

func writeContract(t *testing.T, files map[string][]byte) {
	t.Helper()
	if err := os.RemoveAll(contractDir); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		p := filepath.Join(contractDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestContract generates the cross-language contract files and compares them
// with testdata/contract, or rewrites it with -update.
func TestContract(t *testing.T) {
	if buildinfo.FakeBuild {
		t.Skip("the contract files are the release build's output (app.info marks the rhgfake version)")
	}
	c := buildContract(t)
	checkCompleteness(t, c)
	if *updateContract {
		if t.Failed() {
			t.Fatal("not writing an incomplete contract")
		}
		writeContract(t, c.files)
		return
	}
	got := readContract(t)
	names := make([]string, 0, len(c.files))
	for name := range c.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data, ok := got[name]
		switch {
		case !ok:
			t.Errorf("contract file %s is missing; %s", name, regenerateHint)
		case !bytes.Equal(data, c.files[name]):
			t.Errorf("contract file %s differs; %s\n got: %s\nwant: %s", name, regenerateHint, data, c.files[name])
		}
	}
	for name := range got {
		if _, ok := c.files[name]; !ok {
			t.Errorf("contract file %s is not generated; %s", name, regenerateHint)
		}
	}
}

// TestContract_ParamsDecode proves each params file is a valid input: it
// decodes into its method's params type and re-encodes to the same bytes.
func TestContract_ParamsDecode(t *testing.T) {
	for name, zero := range contractParamTypes {
		data, err := os.ReadFile(filepath.Join(contractDir, "methods", name, "params.json"))
		if err != nil {
			t.Errorf("%s: %v; %s", name, err, regenerateHint)
			continue
		}
		p := reflect.New(reflect.TypeOf(zero))
		if err := decodeParams(data, p.Interface()); err != nil {
			t.Errorf("%s: params.json does not decode: %v", name, err)
			continue
		}
		var s scrubber
		if re := s.canonical(t, mustMarshal(p.Elem().Interface())); !bytes.Equal(re, data) {
			t.Errorf("%s: params.json re-encodes as %s, file is %s", name, re, data)
		}
	}
}

func TestScrubber(t *testing.T) {
	var s scrubber
	s.add("/tmp/x", "/DATA")
	s.add("/tmp/x/sub", "/SUB")
	for in, want := range map[string]string{
		"/tmp/x":                                 "/DATA",
		"/tmp/x/a/b":                             "/DATA/a/b",
		"/tmp/x/sub/c":                           "/SUB/c",
		"/tmp/xy":                                "/tmp/xy",
		"a /tmp/x":                               "a /tmp/x",
		"rhg-bulk-results-2031-12-30-235959.csv": "rhg-bulk-results-2026-01-02-030405.csv",
		"/tmp/x/issuances.json.bak-20311230T235959Z": "/DATA/issuances.json.bak-20260102T030405Z",
	} {
		if got := s.str(in); got != want {
			t.Errorf("str(%q) = %q, want %q", in, got, want)
		}
	}
	got := s.canonical(t, []byte(`{"z":[{"pngPreview":"AAAA"},1.50],"a":"<&>/ა"}`))
	if want := `{"a":"<&>/ა","z":[{"pngPreview":"` + pngPlaceholder + `"},1.50]}` + "\n"; string(got) != want {
		t.Errorf("canonical = %s, want %s", got, want)
	}
}
