package service

import (
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/debuglog"
	"github.com/royalhouseofgeorgia/rhg-authenticator/ghapi"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
)

// --- formatRecordSummary tests ---

func TestFormatRecordSummary(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:      "2026-03-14",
		Recipient: "John Doe",
		Honor:     "Order of the Crown of Georgia",
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "2026-Mar-14") {
		t.Error("summary should contain formatted date")
	}
	if !strings.Contains(got, "John Doe") {
		t.Error("summary should contain recipient")
	}
	if !strings.Contains(got, "Order of the Crown") {
		t.Error("summary should contain honor")
	}
}

func TestFormatRecordSummary_LongHonor(t *testing.T) {
	rec := issuancelog.IssuanceRecord{
		Date:      "2026-03-14",
		Recipient: "John Doe",
		Honor:     "Order of the Eagle of Georgia and the Seamless Tunic of Our Lord Jesus Christ", // Very long title
	}
	got := formatRecordSummary(rec)
	if !strings.Contains(got, "...") {
		t.Error("long honor should be truncated with ellipsis")
	}
}

// --- FormatRecordDetail tests ---

func TestFormatRecordDetail(t *testing.T) {
	rec := HistoryRecord{
		Timestamp:       "2026-03-14T10:30:00Z",
		Recipient:       "John Doe",
		Honor:           "Test Honor",
		Detail:          "Test Detail",
		Date:            "2026-03-14",
		PayloadSHA256:   "abcdef1234567890",
		SignatureB64URL: "dummysig",
	}
	got := FormatRecordDetail(rec)

	for _, field := range []string{
		rec.Timestamp, rec.Recipient, rec.Honor, rec.Detail,
		rec.Date, rec.PayloadSHA256, rec.SignatureB64URL,
	} {
		if !strings.Contains(got, field) {
			t.Errorf("detail should contain %q", field)
		}
	}
}

// --- maxHonorDisplay constant test ---

func TestRevokeConfirmText(t *testing.T) {
	got := RevokeConfirmText(HistoryRecord{Recipient: "John Doe", Date: "2026-03-14"})
	want := "Revoke credential for John Doe dated 2026-Mar-14?\n\nThis cannot be undone."
	if got != want {
		t.Errorf("RevokeConfirmText = %q, want %q", got, want)
	}
}

func TestDuplicatesConfirmText(t *testing.T) {
	if got := DuplicatesConfirmText(0); got != "" {
		t.Errorf("DuplicatesConfirmText(0) = %q, want empty", got)
	}
	want := "Found 3 duplicate entries. The earliest valid entry of each credential is kept and later copies are removed. A backup of the current log is saved first. Continue?"
	if got := DuplicatesConfirmText(3); got != want {
		t.Errorf("DuplicatesConfirmText(3) = %q, want %q", got, want)
	}
	if got := DuplicatesConfirmText(1); !strings.HasPrefix(got, "Found 1 duplicate entry. ") {
		t.Errorf("DuplicatesConfirmText(1) = %q, want the singular", got)
	}
}

func TestDuplicatesRemovedText(t *testing.T) {
	if got := DuplicatesRemovedText(0, ""); got != "" {
		t.Errorf("DuplicatesRemovedText(0) = %q, want empty", got)
	}
	want := "Removed 2 entries. Backup saved to /data/issuances.json.bak-20260102T030405Z."
	if got := DuplicatesRemovedText(2, "/data/issuances.json.bak-20260102T030405Z"); got != want {
		t.Errorf("DuplicatesRemovedText = %q, want %q", got, want)
	}
	if got, want := DuplicatesRemovedText(1, "/b"), "Removed 1 entry. Backup saved to /b."; got != want {
		t.Errorf("DuplicatesRemovedText(1) = %q, want %q", got, want)
	}
}

func TestHasRecords(t *testing.T) {
	tests := map[string]bool{
		"":                       false,
		" \n\t":                  false,
		"[]":                     false,
		"[\n  {},\n  {}\n]":      true,
		"not json":               true, // exported anyway for inspection
		`{"recipient":"object"}`: true,
	}
	for in, want := range tests {
		if got := hasRecords([]byte(in)); got != want {
			t.Errorf("hasRecords(%q) = %v, want %v", in, got, want)
		}
	}
}

// --- History, RefreshHistory ---

var (
	hashA = strings.Repeat("a", 64)
	hashB = strings.Repeat("b", 64)
	hashC = strings.Repeat("c", 64)
)

// validSig is a well-formed (Ed25519-sized) base64url signature.
var validSig = base64.RawURLEncoding.EncodeToString(make([]byte, 64))

func rec(recipient, date, hash string) issuancelog.IssuanceRecord {
	return issuancelog.IssuanceRecord{Recipient: recipient, Date: date, Honor: "Honor", PayloadSHA256: hash, SignatureB64URL: validSig}
}

// writeIssuanceLog writes records as h's issuance log.
func writeIssuanceLog(t *testing.T, h *appHarness, records ...issuancelog.IssuanceRecord) {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	writeRawLog(t, h, string(data))
}

func writeRawLog(t *testing.T, h *appHarness, content string) {
	t.Helper()
	if err := os.WriteFile(h.app.logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// revocationServer serves a revocation list of hashes; status != 200 fails
// the fetch instead. It is pointed at by h's RevocationURL.
func revocationServer(t *testing.T, h *appHarness, status int, hashes ...string) {
	t.Helper()
	list := core.RevocationList{Revocations: []core.RevocationEntry{}}
	for _, hash := range hashes {
		list.Revocations = append(list.Revocations, core.RevocationEntry{Hash: hash, RevokedOn: "2026-01-01"})
	}
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	h.app.revocationURL = srv.URL
}

func summaries(snap HistorySnapshot) []string {
	var out []string
	for _, r := range snap.Rows {
		out = append(out, r.Summary)
	}
	return out
}

func TestRefreshHistory_LoadsRecordsAndRevocations(t *testing.T) {
	h := newAppHarness(t, nil)
	writeIssuanceLog(t, h,
		rec("Alice", "2026-01-01", hashA),
		rec("Bob", "2026-02-01", strings.ToUpper(hashB)), // matched case-insensitively
		rec("Charlie", "2026-03-01", hashC))
	revocationServer(t, h, http.StatusOK, hashB)

	h.app.RefreshHistory()

	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventHistoryChanged, EventRevocationsChanged}) {
		t.Errorf("events = %v", names)
	}
	snap := h.app.History("")
	want := []string{
		"2026-Mar-01 | Charlie | Honor",
		"[REVOKED] 2026-Feb-01 | Bob | Honor",
		"2026-Jan-01 | Alice | Honor",
	}
	if got := summaries(snap); !reflect.DeepEqual(got, want) {
		t.Errorf("summaries = %q, want %q", got, want)
	}
	if !snap.Rows[1].Revoked || snap.Rows[0].Revoked || snap.Rows[2].Revoked {
		t.Errorf("revoked flags wrong: %+v", snap.Rows)
	}
	if snap.Rows[0].Record.Recipient != "Charlie" {
		t.Errorf("row 0 record = %+v", snap.Rows[0].Record)
	}
	if snap.LoadFailed || snap.RevocationsUnavailable || !snap.RevocationsLoaded {
		t.Errorf("flags = %+v", snap)
	}
	if snap.RevokeAvailable {
		t.Error("RevokeAvailable while logged out")
	}
}

func TestHistory_RecordCarriesEveryField(t *testing.T) {
	h := newAppHarness(t, nil)
	full := issuancelog.IssuanceRecord{
		Timestamp:       "2026-03-14T10:30:00Z",
		Recipient:       "Alice",
		Honor:           "Honor",
		Detail:          "For service",
		Date:            "2026-03-14",
		PayloadSHA256:   hashA,
		SignatureB64URL: validSig,
	}
	writeIssuanceLog(t, h, full)
	h.app.RefreshHistory()

	snap := h.app.History("")
	want := HistoryRecord{
		Timestamp:       full.Timestamp,
		Recipient:       full.Recipient,
		Honor:           full.Honor,
		Detail:          full.Detail,
		Date:            full.Date,
		PayloadSHA256:   full.PayloadSHA256,
		SignatureB64URL: full.SignatureB64URL,
	}
	if len(snap.Rows) != 1 || snap.Rows[0].Record != want {
		t.Errorf("rows = %+v, want one with record %+v", snap.Rows, want)
	}
}

func TestHistory_Filter(t *testing.T) {
	h := newAppHarness(t, nil)
	writeIssuanceLog(t, h,
		rec("Alice Smith", "2026-01-01", hashA),
		rec("Bob Jones", "2026-02-01", hashB),
		rec("ALICE Johnson", "2026-03-01", hashC),
		rec("ნინო ბერიძე", "2026-04-01", ""))
	h.app.RefreshHistory()

	for _, tc := range []struct {
		query string
		want  []string // recipients, newest first
	}{
		{"", []string{"ნინო ბერიძე", "ALICE Johnson", "Bob Jones", "Alice Smith"}},
		{"   ", []string{"ნინო ბერიძე", "ALICE Johnson", "Bob Jones", "Alice Smith"}},
		{"alice", []string{"ALICE Johnson", "Alice Smith"}},
		{"  aLiCe ", []string{"ALICE Johnson", "Alice Smith"}},
		{"jo", []string{"ALICE Johnson", "Bob Jones"}},
		{"ბერ", []string{"ნინო ბერიძე"}},
		{"Charlie", nil},
	} {
		var got []string
		for _, r := range h.app.History(tc.query).Rows {
			got = append(got, r.Record.Recipient)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("History(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}

// A decomposed (NFD) query, e.g. pasted from a macOS file name, matches an
// NFC record, and an NFD record matches an NFC query.
func TestHistory_FilterNFC(t *testing.T) {
	h := newAppHarness(t, nil)
	writeIssuanceLog(t, h,
		rec("Jos\u00e9 Ruiz", "2026-01-01", hashA),
		rec("Zoe\u0308 Hart", "2026-02-01", hashB))
	h.app.RefreshHistory()

	for query, want := range map[string]string{"jose\u0301": "Jos\u00e9 Ruiz", "zo\u00eb": "Zoe\u0308 Hart"} {
		rows := h.app.History(query).Rows
		if len(rows) != 1 || rows[0].Record.Recipient != want {
			t.Errorf("History(%+q) = %d rows, want only %+q", query, len(rows), want)
		}
	}
}

func TestHistory_EmptyBeforeLoad(t *testing.T) {
	h := newAppHarness(t, nil)
	snap := h.app.History("")
	if len(snap.Rows) != 0 || snap.Rows == nil || snap.LoadFailed || snap.RevocationsLoaded || snap.RevokeAvailable {
		t.Errorf("snapshot = %+v, want empty", snap)
	}
}

func TestRefreshHistory_OverlapSkipsFetch(t *testing.T) {
	h := newAppHarness(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fetches.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revocations":[]}`))
	}))
	t.Cleanup(srv.Close)
	h.app.revocationURL = srv.URL

	done := make(chan struct{})
	go func() {
		h.app.RefreshHistory()
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first refresh did not reach the revocation fetch")
	}
	h.events.reset()
	writeIssuanceLog(t, h, rec("Late", "2026-03-01", hashA))
	h.app.RefreshHistory() // re-reads the log, skips the fetch (which would block)
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventHistoryChanged}) {
		t.Errorf("overlapping refresh emitted %v, want only %s", names, EventHistoryChanged)
	}
	if rows := h.app.History("").Rows; len(rows) != 1 || rows[0].Record.Recipient != "Late" {
		t.Errorf("rows = %+v, want the record written during the fetch", rows)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first refresh did not finish")
	}
	if !h.app.History("").RevocationsLoaded {
		t.Error("first refresh's result not applied")
	}
	if n := fetches.Load(); n != 1 {
		t.Errorf("revocation fetches = %d, want 1", n)
	}
}

func TestRefreshHistory_MissingLogIsEmpty(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.RefreshHistory()
	if snap := h.app.History(""); len(snap.Rows) != 0 || snap.LoadFailed {
		t.Errorf("snapshot = %+v, want empty, not failed", snap)
	}
}

func TestRefreshHistory_FailuresKeepPreviousData(t *testing.T) {
	h := newAppHarness(t, nil)
	writeIssuanceLog(t, h, rec("Alice", "2026-01-01", hashA))
	revocationServer(t, h, http.StatusOK, hashA)
	h.app.RefreshHistory()

	// Both sources now fail independently.
	writeRawLog(t, h, "not json")
	revocationServer(t, h, http.StatusInternalServerError)
	h.events.reset()
	h.app.RefreshHistory()

	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventHistoryChanged, EventRevocationsChanged}) {
		t.Errorf("events = %v", names)
	}
	snap := h.app.History("")
	if len(snap.Rows) != 1 || !snap.Rows[0].Revoked {
		t.Errorf("rows = %+v, want the previous revoked record", snap.Rows)
	}
	if !snap.LoadFailed || !snap.RevocationsUnavailable || !snap.RevocationsLoaded {
		t.Errorf("flags = %+v", snap)
	}
	log := h.debugLog(t)
	for _, want := range []string{"history: failed to read log: ", "history: failed to fetch revocation list: "} {
		if !strings.Contains(log, want) {
			t.Errorf("debug log missing %q", want)
		}
	}

	// Recovery clears both flags.
	writeIssuanceLog(t, h, rec("Alice", "2026-01-01", hashA), rec("Bob", "2026-02-01", hashB))
	revocationServer(t, h, http.StatusOK)
	h.app.RefreshHistory()
	snap = h.app.History("")
	if len(snap.Rows) != 2 || snap.Rows[1].Revoked || snap.LoadFailed || snap.RevocationsUnavailable {
		t.Errorf("after recovery = %+v", snap)
	}
}

func TestRefreshHistory_NoRevocationURL(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.revocationURL = ""
	h.app.RefreshHistory()
	if snap := h.app.History(""); !snap.RevocationsUnavailable || snap.RevocationsLoaded {
		t.Errorf("snapshot = %+v, want revocations unavailable", snap)
	}
}

func TestHistory_RevokeAvailable(t *testing.T) {
	for _, tc := range []struct {
		name              string
		token             string
		loggedIn, offline bool
		loaded            bool
		want              bool
	}{
		{"online and loaded", "tok", true, false, true, true},
		{"not loaded", "tok", true, false, false, false},
		{"offline", "tok", true, true, true, false},
		{"logged out", "", false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, nil)
			h.app.setAuth(ghapi.Token{AccessToken: tc.token}, "octocat", tc.loggedIn, tc.offline)
			if tc.loaded {
				setRevocations(h)
			}
			if got := h.app.History("").RevokeAvailable; got != tc.want {
				t.Errorf("RevokeAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Revoke ---

// setRevocations marks the revocation list loaded with hashes revoked.
func setRevocations(h *appHarness, hashes ...string) {
	h.app.mu.Lock()
	defer h.app.mu.Unlock()
	h.app.history.revoked = map[string]bool{}
	for _, hash := range hashes {
		h.app.history.revoked[hash] = true
	}
	h.app.history.revocationsLoaded = true
}

// revokeHarness is logged in to a fake GitHub with the revocation list loaded
// (empty) and an issuance log holding a record for hashA.
func revokeHarness(t *testing.T) (*appHarness, *submitFake) {
	t.Helper()
	h := newAppHarness(t, ghapi.NewFakeKeyring())
	f, client := newSubmitFake(t, nil, http.StatusOK)
	logIn(h, client)
	setRevocations(h)
	writeIssuanceLog(t, h, rec("Alice", "2026-01-01", hashA))
	h.app.loadHistory()
	h.events.reset()
	return h, f
}

func historyRevoked(t *testing.T, h *appHarness) bool {
	t.Helper()
	rows := h.app.History("").Rows
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	return rows[0].Revoked
}

func TestRevoke_Submitted(t *testing.T) {
	h, f := revokeHarness(t)
	res, err := h.app.Revoke(context.Background(), strings.ToUpper(hashA))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	prURL := fmt.Sprintf("https://github.com/%s/%s/pull/7", ghapi.DefaultOwner, ghapi.DefaultRepo)
	want := RevokeResult{
		Status:   RevokeSubmitted,
		PRNumber: 7,
		URL:      prURL,
		Title:    "Revocation Submitted",
		Message:  "Pull request #7 created:\n" + prURL + "\n\nIf several revocation PRs are open, merge them one at a time.",
	}
	if res != want {
		t.Errorf("result = %+v\nwant %+v", res, want)
	}
	if !historyRevoked(t, h) {
		t.Error("record not marked revoked")
	}
	hits := f.hitList()
	repo := fmt.Sprintf("/repos/%s/%s", ghapi.DefaultOwner, ghapi.DefaultRepo)
	if len(hits) < 3 || hits[0] != "GET "+repo+"/contents/"+revocationsPath || hits[1] != "GET "+repo+"/pulls" || hits[len(hits)-1] != "POST "+repo+"/pulls" {
		t.Errorf("hits = %v", hits)
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
}

func TestRevoke_NonGitHubPRURLBlanked(t *testing.T) {
	h, f := revokeHarness(t)
	f.prURL = "https://evil.example/pull/7"
	res, err := h.app.Revoke(context.Background(), hashA)
	if err != nil || res.Status != RevokeSubmitted || res.URL != "" || res.PRNumber != 7 {
		t.Errorf("Revoke = %+v, %v; want submitted with a blank URL", res, err)
	}
	if strings.Contains(res.Message, "evil.example") || !strings.HasPrefix(res.Message, "Pull request #7 created.\n\n") {
		t.Errorf("Message = %q, want no unvalidated URL", res.Message)
	}
}

func TestRevoke_NotSubmitted(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*submitFake)
		wantStatus RevokeStatus
		wantTitle  string
		wantMsg    string
	}{
		{"already revoked upstream", func(f *submitFake) {
			f.revocations = `{"revocations":[{"hash":"` + hashA + `","revoked_on":"2026-01-01"}]}`
		}, RevokeAlreadyRevoked, "Already Revoked", ghapi.UserMessage(ghapi.ErrAlreadyRevoked)},
		{"pending", func(f *submitFake) {
			f.openPulls = fmt.Sprintf(`[{"head":{"ref":"revoke-%s-20260101","repo":{"full_name":"%s/%s"}}}]`,
				hashA[:16], ghapi.DefaultOwner, ghapi.DefaultRepo)
		}, RevokePending, "Revocation Pending", ghapi.UserMessage(ghapi.ErrRevocationPending)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, f := revokeHarness(t)
			tc.setup(f)
			res, err := h.app.Revoke(context.Background(), hashA)
			if err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if want := (RevokeResult{Status: tc.wantStatus, Title: tc.wantTitle, Message: tc.wantMsg}); res != want {
				t.Errorf("result = %+v, want %+v", res, want)
			}
			if !historyRevoked(t, h) {
				t.Error("record not marked revoked")
			}
			for _, hit := range f.hitList() {
				if strings.HasPrefix(hit, "POST ") || strings.HasPrefix(hit, "PUT ") {
					t.Errorf("unexpected write %s", hit)
				}
			}
			if !strings.Contains(h.debugLog(t), "info: revocation not submitted: ") {
				t.Error("not-submitted outcome not logged")
			}
		})
	}
}

func TestRevoke_Unauthorized(t *testing.T) {
	h, f := revokeHarness(t)
	kr := h.app.keyring
	if err := ghapi.SaveToken(kr, h.dir, ghapi.Token{AccessToken: "tok", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.revocationsStatus = http.StatusUnauthorized

	_, err := h.app.Revoke(context.Background(), hashA)
	var apiErr *ghapi.APIError
	if !errors.Is(err, ErrSessionExpired) || !ghapi.IsUnauthorized(err) || !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want session expired wrapping the 401", err)
	}
	if err.Error() != "Your GitHub session expired. Please log in again." {
		t.Errorf("text = %q", err.Error())
	}
	if h.app.AuthState() != (AuthState{}) {
		t.Errorf("state = %+v, want logged out", h.app.AuthState())
	}
	if _, err := ghapi.LoadToken(kr, h.dir); err == nil {
		t.Error("token not cleared")
	}
	if historyRevoked(t, h) {
		t.Error("record marked revoked after a failure")
	}
	if !strings.Contains(h.debugLog(t), "warning: revocation unauthorized, logging out") {
		t.Error("401 not logged")
	}
}

func TestRevoke_Failures(t *testing.T) {
	tests := []struct {
		name  string
		hash  string
		setup func(*submitFake)
		hits  bool
	}{
		{"server error", hashA, func(f *submitFake) { f.revocationsStatus = http.StatusInternalServerError }, true},
		{"invalid hash", "not-a-hash", func(*submitFake) {}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, f := revokeHarness(t)
			tc.setup(f)
			_, err := h.app.Revoke(context.Background(), tc.hash)
			if err == nil || ghapi.IsUnauthorized(err) || errors.Is(err, ErrSessionExpired) {
				t.Fatalf("err = %v, want a non-401 error", err)
			}
			if err.Error() != "An error occurred. Please try again later." {
				t.Errorf("text = %q, want ghapi.UserMessage's", err.Error())
			}
			if !h.app.AuthState().LoggedIn {
				t.Error("failure logged out")
			}
			if historyRevoked(t, h) {
				t.Error("record marked revoked after a failure")
			}
			if got := len(f.hitList()) > 0; got != tc.hits {
				t.Errorf("requests made = %v, want %v", got, tc.hits)
			}
			if !strings.Contains(h.debugLog(t), "error: revocation PR failed: ") {
				t.Error("failure not logged")
			}
		})
	}
}

func TestRevoke_Preconditions(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*appHarness)
		wantErr error
		wantRes RevokeResult
	}{
		{"logged out", func(h *appHarness) { h.app.setAuth(ghapi.Token{}, "", false, false) }, ErrNotLoggedIn, RevokeResult{}},
		{"offline", func(h *appHarness) { h.app.setAuth(ghapi.Token{AccessToken: "tok"}, "u", true, true) }, ErrNotLoggedIn, RevokeResult{}},
		{"empty token", func(h *appHarness) { h.app.setAuth(ghapi.Token{}, "u", true, false) }, ErrNotLoggedIn, RevokeResult{}},
		{"revoked locally", func(h *appHarness) { setRevocations(h, hashA) }, nil,
			RevokeResult{Status: RevokeAlreadyRevoked, Title: "Already Revoked", Message: ghapi.UserMessage(ghapi.ErrAlreadyRevoked)}},
		{"revocations not loaded", func(h *appHarness) {
			h.app.mu.Lock()
			h.app.history.revocationsLoaded = false
			h.app.mu.Unlock()
		}, ErrRevocationsNotLoaded, RevokeResult{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, f := revokeHarness(t)
			tc.setup(h)
			res, err := h.app.Revoke(context.Background(), strings.ToUpper(hashA))
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if res != tc.wantRes {
				t.Errorf("result = %+v, want %+v", res, tc.wantRes)
			}
			if hits := f.hitList(); len(hits) != 0 {
				t.Errorf("hits = %v, want none", hits)
			}
		})
	}
}

func TestRevoke_ConcurrentBusy(t *testing.T) {
	h, _ := revokeHarness(t)
	entered, release := make(chan struct{}), make(chan struct{})
	client := h.app.githubClient()
	client.HTTPClient.Transport = &hookTransport{rt: client.HTTPClient.Transport, hook: func() {
		close(entered)
		<-release
	}}
	done := make(chan error, 1)
	go func() {
		_, err := h.app.Revoke(context.Background(), hashA)
		done <- err
	}()
	<-entered
	if _, err := h.app.Revoke(context.Background(), hashB); !errors.Is(err, ErrBusy) {
		t.Errorf("second Revoke err = %v, want ErrBusy", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("first Revoke err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first Revoke did not return")
	}
}

// --- Exports and duplicates ---

func TestIssuanceLogExport(t *testing.T) {
	for _, tc := range []struct {
		name, content string // content "" = no log file
		wantErr       error
	}{
		{"missing log", "", ErrNothingToExport},
		{"empty array", "[]\n", ErrNothingToExport},
		{"whitespace", "  \n", ErrNothingToExport},
		{"has records", `[{"recipient":"x"}]`, nil},
		{"corrupt", "not json", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAppHarness(t, nil)
			if tc.content != "" {
				writeRawLog(t, h, tc.content)
			}
			data, err := h.app.IssuanceLogExport()
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && string(data) != tc.content {
				t.Errorf("data = %q, want %q", data, tc.content)
			}
		})
	}
	if ErrNothingToExport.Error() != "No credentials have been signed on this computer yet." {
		t.Errorf("ErrNothingToExport = %q", ErrNothingToExport)
	}
}

func TestIssuanceLogExport_ReadError(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.logPath = h.dir // a directory can't be read as a file
	_, err := h.app.IssuanceLogExport()
	if err == nil || err.Error() != "Could not read the issuance log." {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(h.debugLog(t), "history: failed to read log for export: ") {
		t.Error("read failure not logged")
	}
}

func TestErrorLogExport(t *testing.T) {
	h := newAppHarness(t, nil)
	h.app.logger.Log("hello diagnostics")
	data, err := h.app.ErrorLogExport()
	if err != nil || !strings.Contains(string(data), "hello diagnostics") {
		t.Errorf("ErrorLogExport = %q, %v", data, err)
	}

	missing := filepath.Join(h.dir, "absent.log")
	h.app.logger = debuglog.New(missing)
	if _, err := h.app.ErrorLogExport(); err == nil || err.Error() != "Could not read the error log." {
		t.Errorf("err = %v", err)
	}
	// The failure is logged to the (now created) log itself.
	if got, _ := os.ReadFile(missing); !strings.Contains(string(got), "errorlog: failed to read log for export: ") {
		t.Errorf("failure not logged: %q", got)
	}
}

func TestDuplicatePreviewAndRemove(t *testing.T) {
	h := newAppHarness(t, nil)
	writeIssuanceLog(t, h, rec("Alice", "2026-01-01", hashA), rec("Bob", "2026-02-01", hashB))
	if n, err := h.app.DuplicatePreview(); err != nil || n != 0 {
		t.Errorf("DuplicatePreview = %d, %v; want 0", n, err)
	}
	if removed, backup, err := h.app.RemoveDuplicates(); err != nil || removed != 0 || backup != "" {
		t.Errorf("RemoveDuplicates = %d, %q, %v; want nothing removed", removed, backup, err)
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none when nothing was removed", names)
	}

	writeIssuanceLog(t, h, rec("Alice", "2026-01-01", hashA), rec("Alice", "2026-01-01", strings.ToUpper(hashA)), rec("Bob", "2026-02-01", hashB))
	h.app.loadHistory()
	h.events.reset()
	if n, err := h.app.DuplicatePreview(); err != nil || n != 1 {
		t.Errorf("DuplicatePreview = %d, %v; want 1", n, err)
	}
	removed, backup, err := h.app.RemoveDuplicates()
	if err != nil || removed != 1 {
		t.Fatalf("RemoveDuplicates = %d, %q, %v", removed, backup, err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Errorf("backup %q: %v", backup, err)
	}
	if rows := h.app.History("").Rows; len(rows) != 2 {
		t.Errorf("history rows = %d, want 2 after reload", len(rows))
	}
	if names := eventNames(h); !reflect.DeepEqual(names, []string{EventHistoryChanged}) {
		t.Errorf("events = %v", names)
	}
}

func TestDuplicates_Errors(t *testing.T) {
	h := newAppHarness(t, nil)
	writeRawLog(t, h, "not json")
	if _, err := h.app.DuplicatePreview(); err == nil || err.Error() != "Could not read the issuance log." {
		t.Errorf("DuplicatePreview err = %v", err)
	}
	if _, _, err := h.app.RemoveDuplicates(); err == nil || err.Error() != "Could not remove duplicates. The issuance log was not changed." {
		t.Errorf("RemoveDuplicates err = %v", err)
	}
	log := h.debugLog(t)
	for _, want := range []string{"history: failed to read log for dedup: ", "history: remove duplicates failed: "} {
		if !strings.Contains(log, want) {
			t.Errorf("debug log missing %q", want)
		}
	}
	if names := eventNames(h); len(names) != 0 {
		t.Errorf("events = %v, want none", names)
	}
}
