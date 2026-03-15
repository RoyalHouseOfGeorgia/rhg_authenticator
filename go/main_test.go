package main

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

func TestRhgTheme_PrimaryColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNamePrimary, theme.VariantDark)
	want := color.NRGBA{R: 0x80, G: 0x00, B: 0x20, A: 0xFF}
	if got != want {
		t.Errorf("Primary color = %v, want %v", got, want)
	}
}

func TestRhgTheme_ButtonColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNameButton, theme.VariantDark)
	want := color.NRGBA{R: 0x80, G: 0x00, B: 0x20, A: 0xFF}
	if got != want {
		t.Errorf("Button color = %v, want %v", got, want)
	}
}

func TestRhgTheme_BackgroundColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNameBackground, theme.VariantLight)
	want := color.NRGBA{R: 0xFA, G: 0xF8, B: 0xF0, A: 0xFF}
	if got != want {
		t.Errorf("Background color = %v, want %v", got, want)
	}
}

func TestRhgTheme_ForegroundColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNameForeground, theme.VariantLight)
	want := color.NRGBA{R: 0x2C, G: 0x2C, B: 0x2C, A: 0xFF}
	if got != want {
		t.Errorf("Foreground color = %v, want %v", got, want)
	}
}

func TestRhgTheme_FallbackColor(t *testing.T) {
	th := &rhgTheme{}
	got := th.Color(theme.ColorNameDisabled, theme.VariantDark)
	want := theme.DefaultTheme().Color(theme.ColorNameDisabled, theme.VariantDark)
	if got != want {
		t.Errorf("Fallback color = %v, want %v (default theme)", got, want)
	}
}

func TestRhgTheme_VariantIndependence(t *testing.T) {
	th := &rhgTheme{}
	// Custom colors should be the same regardless of variant.
	light := th.Color(theme.ColorNamePrimary, theme.VariantLight)
	dark := th.Color(theme.ColorNamePrimary, theme.VariantDark)
	if light != dark {
		t.Errorf("Primary color varies by variant: light=%v, dark=%v", light, dark)
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
