//go:build !windows

package gui

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
)

// TestDesktopDir: <home>/Desktop is used when it exists and skipped when it
// doesn't or the home directory is unknown. t.Setenv makes this test
// non-parallel by design.
func TestDesktopDir(t *testing.T) {
	test.NewTempApp(t)

	t.Setenv("HOME", "")
	if _, ok := desktopDir(); ok {
		t.Error("desktopDir() = true without a home directory")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, ok := desktopDir(); ok {
		t.Error("desktopDir() = true without a Desktop folder")
	}
	if err := os.Mkdir(filepath.Join(home, "Desktop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := desktopDir(); !ok {
		t.Error("desktopDir() = false with a Desktop folder")
	}
}

// showSaveDialogFrom seeds Fyne's last-folder pref with lastFolder, shows a
// save dialog through setDialogLocation (HOME stubbed with a Desktop folder) and
// returns the Desktop path plus the folder the dialog opened in, read back
// from the pref Fyne rewrites on Show(). ReopensLastFolder is only meaningful
// alongside FallsBackToDesktop, which is what fails if Fyne renames the key.
// Fyne logs harmless favorites errors during Show() (e.g. "does not define a
// VIDEOS folder") — expected.
func showSaveDialogFrom(t *testing.T, lastFolder string) (desktop, opened string) {
	t.Helper()
	app := test.NewTempApp(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	desktop = filepath.Join(home, "Desktop")
	if err := os.Mkdir(desktop, 0o755); err != nil {
		t.Fatal(err)
	}
	app.Preferences().SetString(fyneLastFolderKey, storage.NewFileURI(lastFolder).String())

	d := dialog.NewFileSave(func(fyne.URIWriteCloser, error) {}, test.NewWindow(nil))
	setDialogLocation(d)
	d.Show()

	u, err := storage.ParseURI(app.Preferences().String(fyneLastFolderKey))
	if err != nil {
		t.Fatalf("last-folder pref unparsable after Show(): %v", err)
	}
	return desktop, filepath.Clean(u.Path())
}

func TestSetDialogLocation_ReopensLastFolder(t *testing.T) {
	other := t.TempDir()
	if _, opened := showSaveDialogFrom(t, other); opened != other {
		t.Errorf("dialog opened in %q, want last folder %q", opened, other)
	}
}

func TestSetDialogLocation_FallsBackToDesktop(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if desktop, opened := showSaveDialogFrom(t, gone); opened != desktop {
		t.Errorf("dialog opened in %q, want Desktop %q", opened, desktop)
	}
}
