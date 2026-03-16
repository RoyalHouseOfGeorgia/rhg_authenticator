package main

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

func TestRhgTheme_Colors(t *testing.T) {
	th := &rhgTheme{}
	tests := []struct {
		name fyne.ThemeColorName
		want color.Color
	}{
		{theme.ColorNamePrimary, color.NRGBA{0x1B, 0x3A, 0x5C, 0xFF}},
		{theme.ColorNameButton, color.NRGBA{0x1B, 0x3A, 0x5C, 0xFF}},
		{theme.ColorNameForegroundOnPrimary, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameBackground, color.NRGBA{0xF5, 0xF2, 0xEB, 0xFF}},
		{theme.ColorNameForeground, color.NRGBA{0x1A, 0x1A, 0x1A, 0xFF}},
		{theme.ColorNameInputBackground, color.NRGBA{0xFF, 0xFF, 0xFF, 0xFF}},
		{theme.ColorNameDisabled, color.NRGBA{0x8C, 0x8C, 0x8C, 0xFF}},
		{theme.ColorNamePlaceHolder, color.NRGBA{0x6B, 0x6B, 0x6B, 0xFF}},
		{theme.ColorNameHover, color.NRGBA{0x26, 0x4D, 0x73, 0xFF}},
		{theme.ColorNamePressed, color.NRGBA{0x12, 0x2A, 0x42, 0xFF}},
		{theme.ColorNameFocus, color.NRGBA{0x26, 0x4D, 0x73, 0xFF}},
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
	got := th.Color(theme.ColorNameSeparator, theme.VariantDark)
	want := theme.DefaultTheme().Color(theme.ColorNameSeparator, theme.VariantDark)
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
		theme.ColorNamePressed, theme.ColorNameFocus,
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
