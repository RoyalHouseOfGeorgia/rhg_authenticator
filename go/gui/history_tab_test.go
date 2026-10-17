package gui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// Note on test coverage for this file: the login-dependent widget glue in
// NewHistoryTab (signInButton Show/Hide, Revoke re-gating) is deliberately NOT
// driver-tested here. NewHistoryTab kicks off fetchRevocations at construction
// (a real network fetch + goroutine), and under the Fyne test driver its
// fyne.Do body runs inline on that goroutine, racing any synchronous
// refreshLoginState() call (trips -race). The compensating coverage is: the
// pure service.ShouldEnableRevoke table test (the decision logic), the regmgr
// updateLoginUI observer tests (the push wiring), and a manual /verify pass on a
// target platform (the pixels). Do not "add the missing construction test" — it
// reintroduces the race.

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

// TestOnIssuanceExportTapped covers the click-time checks: nothing to export,
// an unreadable log, and a log with records opening the save dialog.
func TestOnIssuanceExportTapped(t *testing.T) {
	test.NewTempApp(t)
	dir := t.TempDir()
	// Keep the non-Windows Desktop lookup off the real home; on Windows the
	// dialog lists the real Desktop, so never confirm a save.
	t.Setenv("HOME", dir)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name           string
		logPath        string
		wantText       string
		wantSaveDialog bool
	}{
		{"missing log", filepath.Join(dir, "absent.json"), "No credentials have been signed", false},
		{"empty array", write("empty.json", "[]\n"), "No credentials have been signed", false},
		{"whitespace", write("blank.json", "  \n"), "No credentials have been signed", false},
		{"unreadable", dir, "could not read the issuance log", false}, // a directory can't be read as a file
		{"has records", write("log.json", `[{"recipient":"x"}]`), "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := test.NewWindow(nil)
			defer w.Close()
			onIssuanceExportTapped(tc.logPath, w)
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
