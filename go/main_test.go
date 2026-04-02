package main

import (
	"image/color"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
)

func TestRhgTheme_Colors(t *testing.T) {
	th := &rhgTheme{}
	tests := []struct {
		name fyne.ThemeColorName
		want color.Color
	}{
		{theme.ColorNamePrimary, color.NRGBA{0x2B, 0x57, 0x9A, 0xFF}},
		{theme.ColorNameButton, color.NRGBA{0x2B, 0x57, 0x9A, 0xFF}},
		{theme.ColorNameForegroundOnPrimary, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameBackground, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameForeground, color.NRGBA{0x33, 0x33, 0x33, 0xFF}},
		{theme.ColorNameInputBackground, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameDisabled, color.NRGBA{0x75, 0x75, 0x75, 0xFF}},
		{theme.ColorNamePlaceHolder, color.NRGBA{0x76, 0x76, 0x76, 0xFF}},
		{theme.ColorNameHover, color.NRGBA{0x2B, 0x57, 0x9A, 0x26}},
		{theme.ColorNamePressed, color.NRGBA{0x2B, 0x57, 0x9A, 0x33}},
		{theme.ColorNameFocus, color.NRGBA{0x00, 0x5A, 0x9E, 0xFF}},
		{theme.ColorNameMenuBackground, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameOverlayBackground, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameSelection, color.NRGBA{0x2B, 0x57, 0x9A, 0x40}},
		{theme.ColorNameDisabledButton, color.NRGBA{0xF3, 0xF2, 0xF1, 0xFF}},
		{theme.ColorNameHeaderBackground, color.NRGBA{0xF3, 0xF2, 0xF1, 0xFF}},
		{theme.ColorNameInputBorder, color.NRGBA{0x8A, 0x88, 0x86, 0xFF}},
		{theme.ColorNameHyperlink, color.NRGBA{0x05, 0x63, 0xC1, 0xFF}},
		{theme.ColorNameScrollBar, color.NRGBA{0xC8, 0xC6, 0xC4, 0xFF}},
		{theme.ColorNameSeparator, color.NRGBA{0xED, 0xEB, 0xE9, 0xFF}},
	}
	for _, tt := range tests {
		got := th.Color(tt.name, theme.VariantLight)
		if got != tt.want {
			t.Errorf("Color(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRhgTheme_FallbackColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNameError, theme.VariantDark)
	want := theme.DefaultTheme().Color(theme.ColorNameError, theme.VariantDark)
	if got != want {
		t.Errorf("Fallback color = %v, want %v (default theme)", got, want)
	}
}

func TestRhgTheme_VariantIndependence(t *testing.T) {
	th := &rhgTheme{}
	names := []fyne.ThemeColorName{
		theme.ColorNamePrimary, theme.ColorNameButton, theme.ColorNameForegroundOnPrimary,
		theme.ColorNameBackground, theme.ColorNameForeground, theme.ColorNameInputBackground,
		theme.ColorNameDisabled, theme.ColorNamePlaceHolder, theme.ColorNameHover,
		theme.ColorNamePressed, theme.ColorNameFocus, theme.ColorNameMenuBackground,
		theme.ColorNameOverlayBackground, theme.ColorNameSelection, theme.ColorNameDisabledButton,
		theme.ColorNameHeaderBackground, theme.ColorNameInputBorder, theme.ColorNameHyperlink,
		theme.ColorNameScrollBar, theme.ColorNameSeparator,
	}
	for _, name := range names {
		light := th.Color(name, theme.VariantLight)
		dark := th.Color(name, theme.VariantDark)
		if light != dark {
			t.Errorf("Color(%s) varies by variant: light=%v, dark=%v", name, light, dark)
		}
	}
}

func TestRhgTheme_Font(t *testing.T) {
	th := &rhgTheme{}
	style := fyne.TextStyle{Bold: true}
	got := th.Font(style)
	want := theme.DefaultTheme().Font(style)
	if got.Name() != want.Name() {
		t.Errorf("Font = %q, want %q", got.Name(), want.Name())
	}
}

func TestRhgTheme_Icon(t *testing.T) {
	th := &rhgTheme{}
	got := th.Icon(theme.IconNameHome)
	want := theme.DefaultTheme().Icon(theme.IconNameHome)
	if got.Name() != want.Name() {
		t.Errorf("Icon = %q, want %q", got.Name(), want.Name())
	}
}

func TestRhgTheme_Size(t *testing.T) {
	th := &rhgTheme{}
	got := th.Size(theme.SizeNamePadding)
	want := theme.DefaultTheme().Size(theme.SizeNamePadding)
	if got != want {
		t.Errorf("Size = %f, want %f", got, want)
	}
}

func TestRhgTheme_ImplementsInterface(t *testing.T) {
	// Compile-time check that rhgTheme implements fyne.Theme.
	var _ fyne.Theme = (*rhgTheme)(nil)
}

// --- buildCloseHandler tests ---

// stubShowConfirm replaces showConfirmFunc for tests, restoring it on cleanup.
// The provided handler receives each dialog's title, message, and callback.
func stubShowConfirm(t *testing.T, handler func(title, msg string, cb func(bool), w fyne.Window)) {
	t.Helper()
	orig := showConfirmFunc
	t.Cleanup(func() { showConfirmFunc = orig })
	showConfirmFunc = handler
}

func TestBuildCloseHandler_ReleaseMode_NotDirty(t *testing.T) {
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return false },
		false, "",
		func() { cleaned = true },
		func(string) { t.Error("openFile called in release mode") },
		func() { quitted = true },
		nil,
	)
	h()
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_ReleaseMode_WithLogFile(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("some log data"), 0o600)

	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return false },
		false, logFile,
		func() { cleaned = true },
		func(string) { t.Error("openFile called in release mode") },
		func() { quitted = true },
		nil,
	)
	h()
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DebugMode_EmptyLog(t *testing.T) {
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return false },
		true, "",
		func() { cleaned = true },
		func(string) { t.Error("openFile called with empty log path") },
		func() { quitted = true },
		nil,
	)
	h()
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DebugMode_MissingLog(t *testing.T) {
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return false },
		true, "/nonexistent/debug.log",
		func() { cleaned = true },
		func(string) { t.Error("openFile called with missing log") },
		func() { quitted = true },
		nil,
	)
	h()
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DebugMode_NonEmptyLog_Open(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("log data"), 0o600)

	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		if title != "Debug Log" {
			t.Errorf("dialog title = %q, want %q", title, "Debug Log")
		}
		cb(true) // simulate "Open File"
	})

	var cleaned, quitted bool
	var openedPath string
	h := buildCloseHandler(
		func() bool { return false },
		true, logFile,
		func() { cleaned = true },
		func(p string) { openedPath = p },
		func() { quitted = true },
		nil,
	)
	h()
	if openedPath != logFile {
		t.Errorf("openFile path = %q, want %q", openedPath, logFile)
	}
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DebugMode_NonEmptyLog_Dismiss(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("log data"), 0o600)

	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		cb(false) // simulate "Dismiss"
	})

	var cleaned, quitted, opened bool
	h := buildCloseHandler(
		func() bool { return false },
		true, logFile,
		func() { cleaned = true },
		func(string) { opened = true },
		func() { quitted = true },
		nil,
	)
	h()
	if opened {
		t.Error("openFile should not be called on dismiss")
	}
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DirtyRegistry_DebugLog(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("log data"), 0o600)

	var dialogTitles []string
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		dialogTitles = append(dialogTitles, title)
		cb(true) // confirm both dialogs
	})

	var cleaned, quitted bool
	var openedPath string
	h := buildCloseHandler(
		func() bool { return true }, // dirty
		true, logFile,
		func() { cleaned = true },
		func(p string) { openedPath = p },
		func() { quitted = true },
		nil,
	)
	h()

	if len(dialogTitles) != 2 {
		t.Fatalf("got %d dialogs, want 2: %v", len(dialogTitles), dialogTitles)
	}
	if dialogTitles[0] != "Unsubmitted Changes" {
		t.Errorf("first dialog = %q, want %q", dialogTitles[0], "Unsubmitted Changes")
	}
	if dialogTitles[1] != "Debug Log" {
		t.Errorf("second dialog = %q, want %q", dialogTitles[1], "Debug Log")
	}
	if openedPath != logFile {
		t.Errorf("openFile path = %q, want %q", openedPath, logFile)
	}
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DirtyRegistry_Cancelled(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("log data"), 0o600)

	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		cb(false) // user cancels unsaved changes dialog
	})

	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return true }, // dirty
		true, logFile,
		func() { cleaned = true },
		func(string) { t.Error("openFile should not be called") },
		func() { quitted = true },
		nil,
	)
	h()
	if cleaned {
		t.Error("cleanup should not run when user cancels")
	}
	if quitted {
		t.Error("quit should not run when user cancels")
	}
}

func TestBuildCloseHandler_CleanupAlwaysRuns(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "debug.log")
	os.WriteFile(logFile, []byte("log data"), 0o600)

	// Dismiss the debug log review — cleanup should still run.
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		cb(false)
	})

	var cleaned bool
	h := buildCloseHandler(
		func() bool { return false },
		true, logFile,
		func() { cleaned = true },
		func(string) {},
		func() {},
		nil,
	)
	h()
	if !cleaned {
		t.Error("cleanup must run regardless of dialog choice")
	}
}

// --- logFileNonEmpty tests ---

func TestLogFileNonEmpty(t *testing.T) {
	if logFileNonEmpty("") {
		t.Error("empty path should return false")
	}
	if logFileNonEmpty("/nonexistent/file.log") {
		t.Error("nonexistent file should return false")
	}

	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.log")
	os.WriteFile(empty, nil, 0o600)
	if logFileNonEmpty(empty) {
		t.Error("empty file should return false")
	}

	nonEmpty := filepath.Join(dir, "nonempty.log")
	os.WriteFile(nonEmpty, []byte("data"), 0o600)
	if !logFileNonEmpty(nonEmpty) {
		t.Error("non-empty file should return true")
	}
}

// Ensure showConfirmFunc defaults to dialog.ShowConfirm (compile-time type check).
var _ func(string, string, func(bool), fyne.Window) = dialog.ShowConfirm
