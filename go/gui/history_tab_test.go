package gui

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	issuancelog "github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

var (
	hashA = strings.Repeat("a", 64)
	hashB = strings.Repeat("b", 64)
	hashC = strings.Repeat("c", 64)
	// validSig is a well-formed (Ed25519-sized) base64url signature.
	validSig = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
)

func issuance(recipient, date, hash string) issuancelog.IssuanceRecord {
	return issuancelog.IssuanceRecord{Recipient: recipient, Date: date, Honor: "Honor", PayloadSHA256: hash, SignatureB64URL: validSig}
}

// historyHarness is a HistoryTab on a real service.App in its own window.
type historyHarness struct {
	tab     *HistoryTab
	svc     *service.App
	logPath string // the service's issuance log
	window  fyne.Window
	logins  int
}

// newHistoryHarness builds a HistoryTab whose service fetches revocations
// from revocationURL ("" = unavailable). It never calls svc.Start; tests load
// the history by calling RefreshHistory on the test goroutine, where the
// test driver runs the event handlers inline.
func newHistoryHarness(t *testing.T, revocationURL string) *historyHarness {
	t.Helper()
	test.NewTempApp(t)
	h := &historyHarness{window: test.NewWindow(nil)}
	t.Cleanup(h.window.Close)
	events := NewEvents()
	h.svc = newTestAppWithConfig(t, func(cfg *service.Config) {
		cfg.Events = events
		cfg.RevocationURL = revocationURL
		h.logPath = filepath.Join(cfg.DataDir, "issuances.json")
	})
	h.tab = NewHistoryTab(h.svc, events, func() { h.logins++ }, h.window)
	h.window.SetContent(h.tab.Content)
	return h
}

// writeLog writes records as the service's issuance log.
func (h *historyHarness) writeLog(t *testing.T, records ...issuancelog.IssuanceRecord) {
	t.Helper()
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	h.writeRawLog(t, string(data))
}

func (h *historyHarness) writeRawLog(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// overlayText joins the label texts of the top dialog.
func (h *historyHarness) overlayText(t *testing.T) string {
	t.Helper()
	return strings.Join(labelTexts(t, topOverlay(t, h.window)), "\n")
}

// overlayHas reports whether the top dialog's text contains want, ignoring
// case (error dialogs capitalize the message).
func (h *historyHarness) overlayHas(t *testing.T, want string) bool {
	t.Helper()
	return strings.Contains(strings.ToLower(h.overlayText(t)), strings.ToLower(want))
}

// revocationServer serves a revocation list of hashes.
func revocationServer(t *testing.T, hashes ...string) string {
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
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func rowSummaries(h *HistoryTab) []string {
	var out []string
	for _, r := range h.snap.Rows {
		out = append(out, r.Summary)
	}
	return out
}

// TestNewHistoryTab_NoFetch: construction does no I/O and shows an empty,
// logged-out tab.
func TestNewHistoryTab_NoFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s during construction", r.URL)
	}))
	t.Cleanup(srv.Close)
	h := newHistoryHarness(t, srv.URL)

	if n := h.tab.list.Length(); n != 0 {
		t.Errorf("list length = %d, want 0", n)
	}
	if !h.tab.revokeButton.Disabled() {
		t.Error("Revoke enabled with nothing selected")
	}
	if !h.tab.signInButton.Visible() {
		t.Error("Connect to GitHub hidden while logged out")
	}
	if h.tab.searchEntry.PlaceHolder != "Search by recipient..." || h.tab.revocationStatus.Text != "" {
		t.Errorf("placeholder %q, revocation status %q", h.tab.searchEntry.PlaceHolder, h.tab.revocationStatus.Text)
	}
	if h.window.Canvas().Overlays().Top() != nil {
		t.Error("construction showed a dialog")
	}
}

func TestHistoryTab_LoginState(t *testing.T) {
	h := newHistoryHarness(t, "")
	for _, tc := range []struct {
		st          service.AuthState
		wantConnect bool
	}{
		{service.AuthState{LoggedIn: true, User: "octocat"}, false},
		{service.AuthState{LoggedIn: true, Offline: true}, true},
		{service.AuthState{}, true},
	} {
		h.tab.applyAuth(tc.st)
		if got := h.tab.signInButton.Visible(); got != tc.wantConnect {
			t.Errorf("%+v: Connect visible = %v, want %v", tc.st, got, tc.wantConnect)
		}
	}

	h.tab.applyAuth(service.AuthState{LoggedIn: true, User: "octocat"})
	h.tab.RefreshLoginState() // the service is logged out
	if !h.tab.signInButton.Visible() {
		t.Error("RefreshLoginState kept Connect hidden while logged out")
	}

	test.Tap(h.tab.signInButton)
	if h.logins != 1 {
		t.Errorf("Connect started %d logins, want 1", h.logins)
	}
}

func TestHistoryTab_HistoryChanged(t *testing.T) {
	h := newHistoryHarness(t, revocationServer(t, hashB))
	h.writeLog(t, issuance("Alice", "2026-01-01", hashA), issuance("Bob", "2026-02-01", hashB), issuance("Charlie", "2026-03-01", hashC))
	h.svc.RefreshHistory()

	want := []string{"2026-Mar-01 | Charlie | Honor", "[REVOKED] 2026-Feb-01 | Bob | Honor", "2026-Jan-01 | Alice | Honor"}
	if got := rowSummaries(h.tab); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rows = %q, want %q", got, want)
	}
	if n := h.tab.list.Length(); n != 3 {
		t.Errorf("list length = %d, want 3", n)
	}
	if h.tab.revocationStatus.Text != "" || h.tab.revocationStatus.Importance != widget.MediumImportance {
		t.Errorf("revocation status = %q (%v)", h.tab.revocationStatus.Text, h.tab.revocationStatus.Importance)
	}
	if h.window.Canvas().Overlays().Top() != nil {
		t.Error("a successful load showed a dialog")
	}

	h.tab.rowSelected(7) // out of range
	if h.tab.selected != -1 || h.window.Canvas().Overlays().Top() != nil {
		t.Errorf("out-of-range selection: selected %d or a dialog shown", h.tab.selected)
	}
	h.tab.list.Select(2)
	if h.tab.selected != 2 {
		t.Errorf("selected = %d, want 2", h.tab.selected)
	}
	if !h.overlayHas(t, "Payload SHA-256: "+hashA) {
		t.Errorf("detail dialog missing the record:\n%s", h.overlayText(t))
	}
	if !h.tab.revokeButton.Disabled() {
		t.Error("Revoke enabled while logged out")
	}

	// A revocation fetch keeps the selection; a log re-read resets it.
	h.tab.revocationsChanged()
	if h.tab.selected != 2 {
		t.Errorf("selected = %d after revocations changed, want 2", h.tab.selected)
	}
	h.tab.historyChanged()
	if h.tab.selected != -1 {
		t.Errorf("selected = %d after history changed, want -1", h.tab.selected)
	}
}

func TestHistoryTab_LoadFailedAndRevocationsUnavailable(t *testing.T) {
	h := newHistoryHarness(t, "")
	h.writeRawLog(t, "not json")
	h.svc.RefreshHistory()

	if !h.overlayHas(t, "unable to load history") {
		t.Errorf("load failure not shown:\n%s", h.overlayText(t))
	}
	if h.tab.revocationStatus.Text != "Revocation unavailable" || h.tab.revocationStatus.Importance != widget.WarningImportance {
		t.Errorf("revocation status = %q (%v)", h.tab.revocationStatus.Text, h.tab.revocationStatus.Importance)
	}
	if !h.tab.revokeButton.Disabled() {
		t.Error("Revoke enabled with revocations unavailable")
	}
}

func TestHistoryTab_Search(t *testing.T) {
	h := newHistoryHarness(t, "")
	h.writeLog(t, issuance("Alice", "2026-01-01", hashA), issuance("Bob", "2026-02-01", hashB))
	h.svc.RefreshHistory()
	h.tab.list.Select(0)

	h.tab.searchEntry.SetText("  aLi ")
	if got := rowSummaries(h.tab); len(got) != 1 || !strings.Contains(got[0], "Alice") {
		t.Errorf("rows = %q, want only Alice", got)
	}
	if h.tab.selected != -1 || !h.tab.revokeButton.Disabled() {
		t.Errorf("search kept selection %d / Revoke enabled", h.tab.selected)
	}
	h.tab.searchEntry.SetText("nobody")
	if n := h.tab.list.Length(); n != 0 {
		t.Errorf("list length = %d, want 0", n)
	}
}

// TestHistoryTab_RevokeTapped covers the confirm dialog; Revoke itself refuses
// rows that can't be revoked (see TestHistoryTab_RevokeDone).
func TestHistoryTab_RevokeTapped(t *testing.T) {
	t.Run("confirm declined", func(t *testing.T) {
		h := newHistoryHarness(t, revocationServer(t, hashB))
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA), issuance("Bob", "2026-02-01", hashB))
		h.svc.RefreshHistory()
		h.tab.selected = 1

		h.tab.revokeTapped()
		if want := "Revoke credential for Alice dated 2026-Jan-01?\n\nThis cannot be undone."; !h.overlayHas(t, want) {
			t.Errorf("dialog missing %q:\n%s", want, h.overlayText(t))
		}
		tapOverlayButton(t, h.window, "No")
		if h.tab.revokeInFlight || h.window.Canvas().Overlays().Top() != nil {
			t.Error("declining the confirm started a revocation or left a dialog")
		}
	})

	t.Run("confirm runs Revoke", func(t *testing.T) {
		h := newHistoryHarness(t, revocationServer(t))
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA))
		h.svc.RefreshHistory()
		logins := make(chan struct{}, 1)
		h.tab.login = func() { logins <- struct{}{} }
		h.tab.selected = 0
		h.tab.revokeTapped()
		tapOverlayButton(t, h.window, "Yes")
		// The service is really logged out, so Revoke returns ErrNotLoggedIn
		// without touching the network and revokeDone starts a login.
		select {
		case <-logins:
		case <-time.After(5 * time.Second):
			t.Fatal("revocation did not finish")
		}
		if h.tab.revokeInFlight {
			t.Error("revokeInFlight still set")
		}
	})
	t.Run("nothing selected", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.tab.revokeTapped()
		if h.window.Canvas().Overlays().Top() != nil {
			t.Error("a dialog was shown with nothing selected")
		}
	})
}

// TestHistoryTab_RevokeDone covers each Revoke outcome.
func TestHistoryTab_RevokeDone(t *testing.T) {
	setup := func(t *testing.T) *historyHarness {
		h := newHistoryHarness(t, "")
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA))
		h.svc.RefreshHistory()
		h.tab.list.Select(0)
		tapOverlayButton(t, h.window, "OK") // the record detail dialog
		h.tab.revokeInFlight = true
		return h
	}

	t.Run("success", func(t *testing.T) {
		h := setup(t)
		h.tab.revokeDone(service.RevokeResult{Status: service.RevokeSubmitted, Title: "Revocation Submitted", Message: "Pull request #7 created"}, nil)
		if h.tab.revokeInFlight || h.tab.selected != -1 || !h.tab.revokeButton.Disabled() {
			t.Errorf("inFlight %v, selected %d, Revoke enabled %v", h.tab.revokeInFlight, h.tab.selected, !h.tab.revokeButton.Disabled())
		}
		if !h.overlayHas(t, "Pull request #7 created") {
			t.Errorf("result not shown:\n%s", h.overlayText(t))
		}
	})
	t.Run("busy", func(t *testing.T) {
		h := setup(t)
		h.tab.revokeDone(service.RevokeResult{}, service.ErrBusy)
		if h.tab.revokeInFlight || h.tab.selected != 0 || h.logins != 0 {
			t.Errorf("inFlight %v, selected %d, logins %d", h.tab.revokeInFlight, h.tab.selected, h.logins)
		}
		if h.window.Canvas().Overlays().Top() != nil {
			t.Error("busy showed a dialog")
		}
	})
	t.Run("not logged in starts login", func(t *testing.T) {
		h := setup(t)
		h.tab.revokeDone(service.RevokeResult{}, service.ErrNotLoggedIn)
		if h.tab.revokeInFlight || h.logins != 1 {
			t.Errorf("inFlight %v, logins %d", h.tab.revokeInFlight, h.logins)
		}
		if h.window.Canvas().Overlays().Top() != nil {
			t.Error("not logged in showed a dialog")
		}
	})
	t.Run("session expired logs in on close", func(t *testing.T) {
		h := setup(t)
		// Wrapped, as Revoke returns it, so an == check would fail.
		h.tab.revokeDone(service.RevokeResult{}, errors.Join(service.ErrSessionExpired))
		if !h.overlayHas(t, "Session Expired") || !h.overlayHas(t, "Your GitHub session expired. Please log in again.") {
			t.Errorf("session expired not shown:\n%s", h.overlayText(t))
		}
		if h.tab.revokeInFlight || h.logins != 0 {
			t.Errorf("inFlight %v, logins %d before closing", h.tab.revokeInFlight, h.logins)
		}
		tapOverlayButton(t, h.window, "OK")
		if h.logins != 1 {
			t.Errorf("logins = %d after closing, want 1", h.logins)
		}
	})
	t.Run("other error offers the log", func(t *testing.T) {
		h := setup(t)
		h.tab.revokeDone(service.RevokeResult{}, errors.New("An error occurred. Please try again later."))
		if h.tab.revokeInFlight || h.logins != 0 || h.tab.selected != 0 {
			t.Errorf("inFlight %v, logins %d, selected %d", h.tab.revokeInFlight, h.logins, h.tab.selected)
		}
		if findButton(t, topOverlay(t, h.window), "Export Error Log…") == nil ||
			!h.overlayHas(t, "Revocation Failed") || !h.overlayHas(t, "An error occurred. Please try again later.") {
			t.Errorf("no log export offered:\n%s", h.overlayText(t))
		}
	})
}

func TestHistoryTab_ExportButton(t *testing.T) {
	h := newHistoryHarness(t, "")
	test.Tap(findButton(t, h.tab.Content, "Export Issuance Log…"))
	if !h.overlayHas(t, "No credentials have been signed on this computer yet.") {
		t.Errorf("nothing-to-export not shown:\n%s", h.overlayText(t))
	}
}

func TestHistoryTab_RemoveDuplicates(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA))
		test.Tap(findButton(t, h.tab.Content, "Remove Duplicates…"))
		if !h.overlayHas(t, "The issuance log has no duplicate entries.") {
			t.Errorf("no-duplicates not shown:\n%s", h.overlayText(t))
		}
	})
	t.Run("preview fails", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeRawLog(t, "not json")
		onRemoveDuplicatesTapped(h.svc, h.window)
		if !h.overlayHas(t, "Could not read the issuance log.") {
			t.Errorf("preview failure not shown:\n%s", h.overlayText(t))
		}
		if findButton(t, topOverlay(t, h.window), "Export Error Log…") == nil {
			t.Error("no log export offered")
		}
	})
	t.Run("confirm removes and reloads", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA), issuance("Alice", "2026-01-01", hashA), issuance("Bob", "2026-02-01", hashB))
		h.svc.RefreshHistory()
		onRemoveDuplicatesTapped(h.svc, h.window)
		if !h.overlayHas(t, "Found 1 duplicate entries.") {
			t.Fatalf("confirm not shown:\n%s", h.overlayText(t))
		}
		tapOverlayButton(t, h.window, "Remove Entries")
		if !h.overlayHas(t, "Removed 1 entries. Backup saved to ") {
			t.Errorf("removal not reported:\n%s", h.overlayText(t))
		}
		if n := h.tab.list.Length(); n != 2 {
			t.Errorf("list length = %d after removal, want 2", n)
		}
	})
	t.Run("cancel changes nothing", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA), issuance("Alice", "2026-01-01", hashA))
		onRemoveDuplicatesTapped(h.svc, h.window)
		tapOverlayButton(t, h.window, "Cancel")
		if n, err := h.svc.DuplicatePreview(); err != nil || n != 1 {
			t.Errorf("DuplicatePreview = %d, %v after cancel; want 1", n, err)
		}
	})
	t.Run("removed nothing", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeLog(t, issuance("Alice", "2026-01-01", hashA))
		removeDuplicatesConfirmed(h.svc, h.window)
		if !h.overlayHas(t, "The issuance log has no duplicate entries.") {
			t.Errorf("no-duplicates not shown:\n%s", h.overlayText(t))
		}
	})
	t.Run("remove fails", func(t *testing.T) {
		h := newHistoryHarness(t, "")
		h.writeRawLog(t, "not json")
		removeDuplicatesConfirmed(h.svc, h.window)
		if !h.overlayHas(t, "Could not remove duplicates. The issuance log was not changed.") {
			t.Errorf("removal failure not shown:\n%s", h.overlayText(t))
		}
	})
}

// TestOnIssuanceExportChosen covers the export save callback: success,
// save-dialog error, cancel, and a failed write. Each case gets its own
// window so overlays don't leak between cases.
func TestOnIssuanceExportChosen(t *testing.T) {
	test.NewTempApp(t)
	data := []byte(`[{"recipient":"ქართველი"}]`)
	dest := filepath.Join(t.TempDir(), "rhg-issuances.json")

	tests := []struct {
		name      string
		writer    *fakeURIWriter
		err       error
		wantText  string // "" = no dialog expected
		wantBytes bool
	}{
		{"success", &fakeURIWriter{path: dest}, nil, "Saved to:", true},
		// Fyne passes a writer alongside the error when it can't create the file.
		{"save dialog error", &fakeURIWriter{path: dest}, errors.New("permission denied"), "could not save the issuance log", false},
		{"cancelled", nil, nil, "", false},
		{"write fails", &fakeURIWriter{path: dest, failWrite: true}, nil, "could not save the issuance log", false},
		{"close fails", &fakeURIWriter{path: dest, failClose: true}, nil, "could not save the issuance log", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := test.NewWindow(nil)
			defer w.Close()
			var writer fyne.URIWriteCloser
			if tc.writer != nil {
				writer = tc.writer
			}
			onIssuanceExportChosen(data, w, writer, tc.err)

			if tc.wantText == "" {
				if w.Canvas().Overlays().Top() != nil {
					t.Fatal("expected no dialog")
				}
				return
			}
			texts := strings.Join(labelTexts(t, topOverlay(t, w)), "\n")
			if !strings.Contains(strings.ToLower(texts), strings.ToLower(tc.wantText)) {
				t.Errorf("dialog missing %q:\n%s", tc.wantText, texts)
			}
			if tc.err != nil {
				if tc.writer.buf.Len() != 0 || tc.writer.closed {
					t.Error("writer used despite save-dialog error")
				}
			} else if tc.writer != nil && !tc.writer.closed {
				t.Error("writer not closed")
			}
			if tc.wantBytes {
				if got := tc.writer.buf.Bytes(); string(got) != string(data) {
					t.Errorf("wrote %q, want %q", got, data)
				}
				if !strings.Contains(texts, filepath.FromSlash(dest)) {
					t.Errorf("confirmation missing path %q:\n%s", dest, texts)
				}
			}
		})
	}
}

// TestOnIssuanceExportTapped covers the click-time outcomes of the export
// read: nothing to export, a read error, and records opening the save dialog.
func TestOnIssuanceExportTapped(t *testing.T) {
	test.NewTempApp(t)
	// Keep the non-Windows Desktop lookup off the real home; on Windows the
	// dialog lists the real Desktop, so never confirm a save.
	t.Setenv("HOME", t.TempDir())

	tests := []struct {
		name           string
		data           []byte
		err            error
		wantText       string
		wantSaveDialog bool
	}{
		{"nothing to export", nil, service.ErrNothingToExport, "No credentials have been signed", false},
		{"read error", nil, errors.New("could not read the issuance log"), "could not read the issuance log", false},
		{"has records", []byte(`[{"recipient":"x"}]`), nil, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := test.NewWindow(nil)
			defer w.Close()
			onIssuanceExportTapped(func() ([]byte, error) { return tc.data, tc.err }, w)
			texts := strings.Join(labelTexts(t, topOverlay(t, w)), "\n")
			if tc.wantSaveDialog {
				if findButton(t, topOverlay(t, w), "Save") == nil {
					t.Errorf("save dialog not shown:\n%s", texts)
				}
				return
			}
			if !strings.Contains(strings.ToLower(texts), strings.ToLower(tc.wantText)) {
				t.Errorf("dialog missing %q:\n%s", tc.wantText, texts)
			}
		})
	}
}
