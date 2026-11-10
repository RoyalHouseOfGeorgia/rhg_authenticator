//go:build windows

package yubikey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// winscardAtStart is where winscard.dll was loaded from once this package
// was initialized, before any test touched a card ("" if it was not loaded).
// Captured in TestMain: a test that talks to piv-go loads the library itself.
var winscardAtStart string

func TestMain(m *testing.M) {
	winscardAtStart = loadedModuleDir("winscard.dll")
	os.Exit(m.Run())
}

// loadedModuleDir returns the directory a module with the given name was
// loaded from, or "" if no such module is loaded.
func loadedModuleDir(name string) string {
	var module windows.Handle
	if windows.GetModuleHandleEx(0, windows.StringToUTF16Ptr(name), &module) != nil {
		return ""
	}
	defer windows.FreeLibrary(module)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(module, &buf[0], uint32(len(buf)))
	if err != nil {
		return ""
	}
	return filepath.Dir(windows.UTF16ToString(buf[:n]))
}

// TestWinscardIsLoadedFromSystem32 checks that the PC/SC library is loaded
// by package initialization alone, and from System32, so piv-go's later load
// by bare name never reaches a Winscard.dll beside the executable.
func TestWinscardIsLoadedFromSystem32(t *testing.T) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	if winscardAtStart == "" {
		t.Fatal("winscard.dll was not loaded at package initialization")
	}
	if !strings.EqualFold(winscardAtStart, system) {
		t.Fatalf("winscard.dll loaded from %s, want %s", winscardAtStart, system)
	}
}
