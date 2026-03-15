package main

import (
	_ "embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"

	"github.com/royalhouseofgeorgia/rhg-authenticator/regmgr"
)

//go:embed icon.png
var appIconData []byte

func main() {
	a := app.NewWithID("ge.royalhouseofgeorgia.rhg-regmgr")
	appIcon := fyne.NewStaticResource("icon.png", appIconData)
	a.SetIcon(appIcon)
	a.Settings().SetTheme(&rhgTheme{})
	window := a.NewWindow("RHG Registry Manager")
	window.Resize(fyne.NewSize(900, 650))

	content := regmgr.NewApp(window)
	window.SetContent(content)
	window.ShowAndRun()
}

// rhgTheme implements fyne.Theme with a burgundy/cream color scheme.
type rhgTheme struct{}

func (t *rhgTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x80, G: 0x00, B: 0x20, A: 0xFF} // #800020 burgundy
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x80, G: 0x00, B: 0x20, A: 0xFF}
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0xFA, G: 0xF8, B: 0xF0, A: 0xFF} // #FAF8F0 cream
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0x2C, G: 0x2C, B: 0x2C, A: 0xFF} // #2c2c2c
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *rhgTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *rhgTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *rhgTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
