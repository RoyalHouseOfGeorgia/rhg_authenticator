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

// TestOnErrorLogExportChosen covers the error-log save callback: success,
// save-dialog error (writer plus error), cancel, and failed write/close. Each
// case gets its own window so overlays don't leak between cases.
func TestOnErrorLogExportChosen(t *testing.T) {
	test.NewTempApp(t)
	data := []byte("2026-09-30T10:00:00Z startup version=1.2.3\n")
	dest := filepath.Join(t.TempDir(), "rhg-error-log.log")

	tests := []struct {
		name      string
		writer    *fakeURIWriter
		err       error
		wantText  string // "" = no dialog expected
		wantBytes bool
	}{
		{"success", &fakeURIWriter{path: dest}, nil, "no PINs or keys", true},
		// Fyne passes a writer alongside the error when it can't create the file.
		{"save dialog error", &fakeURIWriter{path: dest}, errors.New("permission denied"), "could not save the error log", false},
		{"cancelled", nil, nil, "", false},
		{"write fails", &fakeURIWriter{path: dest, failWrite: true}, nil, "could not save the error log", false},
		{"close fails", &fakeURIWriter{path: dest, failClose: true}, nil, "could not save the error log", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := test.NewWindow(nil)
			defer w.Close()
			var writer fyne.URIWriteCloser
			if tc.writer != nil {
				writer = tc.writer
			}
			onErrorLogExportChosen(data, w, writer, tc.err)

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
			} else if !tc.writer.closed {
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

// TestOnErrorLogExportTapped: an unreadable or missing log shows an error
// (never a save dialog); a readable log opens the save dialog.
func TestOnErrorLogExportTapped(t *testing.T) {
	test.NewTempApp(t)
	dir := t.TempDir()
	// Keep the save dialog's Desktop lookup off the real home directory.
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	logPath := filepath.Join(dir, "debug.log")
	if err := os.WriteFile(logPath, []byte("startup\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		logPath        string
		wantSaveDialog bool
	}{
		{"missing log", filepath.Join(dir, "absent.log"), false},
		{"unreadable", dir, false}, // a directory can't be read as a file
		{"readable log", logPath, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := test.NewWindow(nil)
			defer w.Close()
			OnErrorLogExportTapped(tc.logPath, w)
			top := topOverlay(t, w)
			hasSave := findButton(t, top, "Save") != nil
			if hasSave != tc.wantSaveDialog {
				t.Fatalf("save dialog shown = %v, want %v", hasSave, tc.wantSaveDialog)
			}
			if !tc.wantSaveDialog {
				texts := strings.Join(labelTexts(t, top), "\n")
				if !strings.Contains(strings.ToLower(texts), "could not read the error log") {
					t.Errorf("error dialog missing read failure:\n%s", texts)
				}
			}
		})
	}
}

// TestShowErrorWithLogExport: the dialog shows the message with both buttons;
// OK dismisses without exporting, and Export opens the save dialog (started on
// the Desktop) whose Cancel leaves nothing behind.
func TestShowErrorWithLogExport(t *testing.T) {
	test.NewTempApp(t)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	if err := os.Mkdir(filepath.Join(dir, "Desktop"), 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "debug.log")
	if err := os.WriteFile(logPath, []byte("startup\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("OK dismisses without export", func(t *testing.T) {
		w := test.NewWindow(nil)
		defer w.Close()
		ShowErrorWithLogExport("Signing Failed", "The YubiKey was removed.", logPath, w)
		texts := strings.Join(labelTexts(t, topOverlay(t, w)), "\n")
		if !strings.Contains(texts, "The YubiKey was removed.") {
			t.Errorf("dialog missing message:\n%s", texts)
		}
		if findButton(t, topOverlay(t, w), "Export Error Log…") == nil {
			t.Fatal("no export button")
		}
		tapOverlayButton(t, w, "OK")
		if top := w.Canvas().Overlays().Top(); top != nil {
			t.Fatal("dialog still shown after OK (or export triggered)")
		}
	})

	t.Run("Export opens save dialog, Cancel closes it", func(t *testing.T) {
		w := test.NewWindow(nil)
		defer w.Close()
		ShowErrorWithLogExport("Signing Failed", "The YubiKey was removed.", logPath, w)
		tapOverlayButton(t, w, "Export Error Log…")
		if findButton(t, topOverlay(t, w), "Save") == nil {
			t.Fatal("save dialog not shown after export")
		}
		tapOverlayButton(t, w, "Cancel") // save callback with a nil writer
		if top := w.Canvas().Overlays().Top(); top != nil {
			t.Fatal("dialog still shown after cancelling the save")
		}
	})
}
