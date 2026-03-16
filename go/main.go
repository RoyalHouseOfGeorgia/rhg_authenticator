package main

import (
	_ "embed"
	"fmt"
	"image/color"
	"os"
	"path/filepath"

	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/regmgr"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

//go:embed icon.png
var appIconData []byte

var version = "dev"

func main() {
	// 1. Create Fyne app and window.
	a := app.NewWithID("ge.royalhouseofgeorgia.rhg-authenticator")
	appIcon := fyne.NewStaticResource("icon.png", appIconData)
	a.SetIcon(appIcon)
	a.Settings().SetTheme(&rhgTheme{})
	window := a.NewWindow("RHG Authenticator")
	window.Resize(fyne.NewSize(800, 600))

	// 2. Data directory.
	configDir, err := os.UserConfigDir()
	if err != nil {
		fatalDialog(window, fmt.Sprintf("Cannot determine config directory: %v", err))
		return
	}
	dataDir := filepath.Join(configDir, "rhg-authenticator")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fatalDialog(window, fmt.Sprintf("Cannot create data directory: %v", err))
		return
	}

	// 3. Log path and cleanup.
	logPath := filepath.Join(dataDir, "issuances.json")
	if err := log.CleanStaleTmpFiles(logPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: log cleanup failed: %v\n", err)
	}

	// 4. Fetch registry (remote only — no cache or embedded fallback).
	reg, err := registry.FetchRegistry(registry.DefaultRegistryURL)
	regOnline := err == nil
	if !regOnline {
		fmt.Fprintf(os.Stderr, "warning: registry fetch failed: %v\n", err)
		reg = core.Registry{}
	}

	// 5. Build tabs.
	signContent, signCleanup := gui.NewSignTab(gui.SignTabConfig{
		LogPath: logPath,
		DataDir: dataDir,
	}, window)
	historyContent := gui.NewHistoryTab(logPath, window)
	regTab := regmgr.NewRegistryTab(window)
	auditContent := gui.NewAuditTab(window)
	yubiKeyContent := gui.NewYubiKeyTab(reg, regOnline, window)

	signTab := container.NewTabItem("Sign", signContent)
	historyTab := container.NewTabItem("History", historyContent)
	registryTab := container.NewTabItem("Registry", regTab.Content)
	auditTab := container.NewTabItem("Audit", auditContent)
	yubiKeyTab := container.NewTabItem("YubiKey", yubiKeyContent)

	// 6. Set content.
	tabs := container.NewAppTabs(signTab, historyTab, registryTab, auditTab, yubiKeyTab)
	statusBar := gui.NewStatusBar(reg, regOnline)
	updateBanner := container.NewVBox()
	windowContent := container.NewBorder(updateBanner, statusBar, nil, nil, tabs)
	window.SetContent(windowContent)

	// 7. Close intercept for unsaved registry changes + PIN cache cleanup.
	window.SetCloseIntercept(func() {
		if regTab.IsDirty() {
			dialog.ShowConfirm("Unsaved Changes",
				"The registry has unsaved changes. Exit anyway?",
				func(ok bool) {
					if ok {
						signCleanup()
						a.Quit()
					}
				}, window)
		} else {
			signCleanup()
			a.Quit()
		}
	})

	// 8. Non-blocking registry tab fetch.
	go func() {
		regTab.Fetch()
	}()

	// 9. Non-blocking version check.
	go func() {
		result := update.Check("RoyalHouseOfGeorgia", "rhg_authenticator", version)
		if result.UpdateAvailable {
			u, err := url.Parse(result.DownloadURL)
			if err != nil || u.Scheme != "https" {
				return
			}
			fyne.Do(func() {
				updateBanner.Add(container.NewHBox(
					widget.NewLabel(fmt.Sprintf("Version %s available —", result.LatestVersion)),
					widget.NewHyperlink("Download", u),
				))
			})
		}
	}()

	window.ShowAndRun()
}

// fatalDialog shows an error dialog and exits after the user dismisses it.
func fatalDialog(window fyne.Window, message string) {
	d := dialog.NewError(fmt.Errorf("%s", message), window)
	d.SetOnClosed(func() {
		os.Exit(1)
	})
	d.Show()
	window.ShowAndRun()
}

// rhgTheme implements fyne.Theme with a Microsoft Office / Fluent UI color scheme.
type rhgTheme struct{}

func (t *rhgTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0xFF} // #2B579A Office blue
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0xFF} // #2B579A Office blue
	case theme.ColorNameForegroundOnPrimary:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF white on blue
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF white
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xFF} // #333333 body text
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF white inputs
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x75, G: 0x75, B: 0x75, A: 0xFF} // #757575 WCAG AA
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x76, G: 0x76, B: 0x76, A: 0xFF} // #767676 WCAG AA
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x26} // ~15% blue overlay
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x33} // ~20% blue overlay
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0x00, G: 0x5A, B: 0x9E, A: 0xFF} // #005A9E distinct focus
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF white popups
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF} // #FFFFFF dialog panels
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x2B, G: 0x57, B: 0x9A, A: 0x40} // ~25% blue selection
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0xF3, G: 0xF2, B: 0xF1, A: 0xFF} // #F3F2F1 Fluent disabled
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0xF3, G: 0xF2, B: 0xF1, A: 0xFF} // #F3F2F1 Fluent neutral
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x8A, G: 0x88, B: 0x86, A: 0xFF} // #8A8886 Fluent tertiary
	case theme.ColorNameHyperlink:
		return color.NRGBA{R: 0x05, G: 0x63, B: 0xC1, A: 0xFF} // #0563C1 Office link
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0xC8, G: 0xC6, B: 0xC4, A: 0xFF} // #C8C6C4 Fluent quaternary
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 0xED, G: 0xEB, B: 0xE9, A: 0xFF} // #EDEBE9 Fluent light
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
