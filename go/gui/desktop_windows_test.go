package gui

import (
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2/test"
)

// TestDesktopDir_Windows: the shell-reported Desktop is an absolute path the
// save dialog can start in. (OneDrive redirection itself is checked by hand;
// CI runners have a plain Desktop.)
func TestDesktopDir_Windows(t *testing.T) {
	test.NewTempApp(t) // registers the file repository desktopDir lists with

	p := desktopPath()
	if p == "" {
		t.Fatal("desktopPath() = \"\"; the shell reported no Desktop")
	}
	if !filepath.IsAbs(p) {
		t.Errorf("desktopPath() = %q, want an absolute path", p)
	}
	if _, ok := desktopDir(); !ok {
		t.Errorf("desktopDir() = false for %q", p)
	}
}
