//go:build !windows

package gui

import (
	"os"
	"path/filepath"
	"testing"

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
