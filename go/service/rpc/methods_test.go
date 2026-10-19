package rpc

import (
	"reflect"
	"strings"
	"testing"

	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// appMethods maps each exposed *service.App method to its rpc method.
var appMethods = map[string]string{
	"Info":              "app.info",
	"ExportErrorLog":    "app.exportErrorLog",
	"Honors":            "sign.honors",
	"Sign":              "sign.sign",
	"SaveQR":            "sign.saveQR",
	"ReportSignError":   "sign.reportError",
	"LoadBulk":          "bulk.load",
	"RunBulk":           "bulk.run",
	"CancelBulk":        "bulk.cancel",
	"ExportBulkResults": "bulk.exportResults",
	"CheckYubiKey":      "yubikey.check",
	"AuthState":         "auth.state",
	"Login":             "auth.login",
	"CancelLogin":       "auth.cancelLogin",
	"Logout":            "auth.logout",
	"Registry":          "registry.snapshot",
	"FetchRegistry":     "registry.fetch",
	"AddEntry":          "registry.addEntry",
	"UpdateEntry":       "registry.updateEntry",
	"ImportCertificate": "registry.importCertificate",
	"ImportFromYubiKey": "registry.importFromYubiKey",
	"SubmitRegistry":    "registry.submit",
	"RefreshHistory":    "history.refresh",
	"History":           "history.list",
	"Revoke":            "history.revoke",
	"ExportIssuanceLog": "history.exportIssuanceLog",
	"DuplicatePreview":  "history.duplicatePreview",
	"RemoveDuplicates":  "history.removeDuplicates",
	"AuditCommits":      "audit.commits",
	"Start":             "app.start",
	"Close":             "app.shutdown",
	"Dirty":             "app.canQuit",
}

// excludedAppMethods are the *service.App methods deliberately not exposed:
// they serve the Fyne UI's in-memory save flow or are covered by another
// method.
var excludedAppMethods = []string{"IssuanceLogExport", "ErrorLogExport"}

// nonAppMethods are rpc methods backed by package-level service functions,
// SignFields or the server itself.
var nonAppMethods = []string{
	"sign.validate", "registry.columns", "history.recordText",
	"app.init", "pin.submit", "pin.cancel", "update.current",
}

// TestMethodTable_CoversApp fails when an exported *service.App method is
// neither exposed nor explicitly excluded, so a new service method can't be
// silently missed.
func TestMethodTable_CoversApp(t *testing.T) {
	table := methodTable()
	appType := reflect.TypeOf(&service.App{})
	excluded := map[string]bool{}
	for _, m := range excludedAppMethods {
		excluded[m] = true
		if _, ok := appType.MethodByName(m); !ok {
			t.Errorf("excluded method %s no longer exists", m)
		}
	}
	for i := range appType.NumMethod() {
		name := appType.Method(i).Name
		if excluded[name] {
			continue
		}
		rpcName, ok := appMethods[name]
		if !ok {
			t.Errorf("App.%s is neither exposed nor excluded", name)
			continue
		}
		if table[rpcName] == nil {
			t.Errorf("App.%s maps to %s, which is not in the method table", name, rpcName)
		}
	}
	mapped := map[string]bool{}
	for goName, rpcName := range appMethods {
		if _, ok := appType.MethodByName(goName); !ok {
			t.Errorf("mapped method App.%s does not exist", goName)
		}
		mapped[rpcName] = true
	}
	for _, m := range nonAppMethods {
		mapped[m] = true
	}
	for name := range table {
		if !mapped[name] {
			t.Errorf("method %s is not accounted for", name)
		}
	}
	if len(table) != len(appMethods)+len(nonAppMethods) {
		t.Errorf("table has %d methods, want %d", len(table), len(appMethods)+len(nonAppMethods))
	}
}

func TestMethodNames(t *testing.T) {
	for name := range methodTable() {
		ns, m, ok := strings.Cut(name, ".")
		if !ok || ns == "" || m == "" || strings.ContainsAny(m, ".-_ ") || m[0] < 'a' || m[0] > 'z' {
			t.Errorf("method name %q is not namespace.lowerCamel", name)
		}
	}
}

// BenchmarkHistoryList measures history.list over a 10,000-record log.
func BenchmarkHistoryList(b *testing.B) {
	h := newHarness(b, nil)
	recs := make([]issuancelog.IssuanceRecord, 10000)
	for i := range recs {
		recs[i] = record(i, "Recipient "+strings.Repeat("x", i%20))
	}
	writeRecords(b, h.dir, recs)
	h.call(b, "history.refresh", ``).ok(b, nil)
	var snap service.HistorySnapshot
	h.call(b, "history.list", `{"query":""}`).ok(b, &snap)
	if len(snap.Rows) != len(recs) {
		b.Fatalf("rows = %d, want %d", len(snap.Rows), len(recs))
	}
	params := []byte(`{"query":""}`)
	b.ReportAllocs()
	for b.Loop() {
		h.srv.Dispatch("history.list", params)
	}
}
