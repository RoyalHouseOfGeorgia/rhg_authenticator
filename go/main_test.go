package main

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/test"
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
	// As of fyne 2.8.0, the built-in theme's Color() dereferences the current
	// Fyne app (theme.go:109), so the DefaultTheme() fallback path panics unless
	// an app is registered. Provide a test app for the duration of this test.
	test.NewTempApp(t)

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

func TestBuildCloseHandler_NotDirty(t *testing.T) {
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		t.Errorf("unexpected dialog %q", title)
	})
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return false },
		func() { cleaned = true },
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

func TestBuildCloseHandler_DirtyRegistry_Confirmed(t *testing.T) {
	var dialogTitles []string
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		dialogTitles = append(dialogTitles, title)
		cb(true)
	})
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return true },
		func() { cleaned = true },
		func() { quitted = true },
		nil,
	)
	h()
	if len(dialogTitles) != 1 || dialogTitles[0] != "Unsubmitted Changes" {
		t.Errorf("dialogs = %v, want [Unsubmitted Changes]", dialogTitles)
	}
	if !cleaned {
		t.Error("cleanup not called")
	}
	if !quitted {
		t.Error("quit not called")
	}
}

func TestBuildCloseHandler_DirtyRegistry_Cancelled(t *testing.T) {
	stubShowConfirm(t, func(title, msg string, cb func(bool), w fyne.Window) {
		cb(false) // user cancels unsaved changes dialog
	})
	var cleaned, quitted bool
	h := buildCloseHandler(
		func() bool { return true },
		func() { cleaned = true },
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

// Ensure showConfirmFunc defaults to dialog.ShowConfirm (compile-time type check).
var _ func(string, string, func(bool), fyne.Window) = dialog.ShowConfirm

func TestBuildMainMenu(t *testing.T) {
	called := false
	mm := buildMainMenu(func() { called = true })

	var file, help *fyne.Menu
	for _, m := range mm.Items {
		switch m.Label {
		case "File":
			file = m
		case "Help":
			help = m
		}
	}
	if file == nil {
		t.Fatal("File menu missing")
	}
	if help == nil {
		t.Fatal("Help menu missing")
	}
	var export *fyne.MenuItem
	for _, it := range help.Items {
		if it.Label == "Export Error Log…" {
			export = it
		}
	}
	if export == nil || export.Action == nil {
		t.Fatal("Help → Export Error Log… missing or has no action")
	}
	export.Action()
	if !called {
		t.Error("Export Error Log… action did not invoke callback")
	}
}
