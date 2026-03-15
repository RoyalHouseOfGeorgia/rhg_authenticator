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

	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

//go:embed keys/registry.json
var embeddedRegistry []byte

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

	// 4. Fetch registry (remote -> cache -> embedded).
	cachePath := filepath.Join(dataDir, "registry.cache.json")
	reg, _, err := registry.FetchRegistry(registry.DefaultRegistryURL, cachePath, embeddedRegistry)
	if err != nil {
		fatalDialog(window, fmt.Sprintf("Failed to load key registry: %v", err))
		return
	}

	// 5. Build tabs.
	signContent := gui.NewSignTab(gui.SignTabConfig{
		Registry: reg,
		LogPath:  logPath,
		DataDir:  dataDir,
	}, window)
	historyContent := gui.NewHistoryTab(logPath, window)

	signTab := container.NewTabItem("Sign", signContent)
	historyTab := container.NewTabItem("History", historyContent)

	// 6. Set content.
	tabs := container.NewAppTabs(signTab, historyTab)
	updateBanner := container.NewVBox()
	windowContent := container.NewBorder(updateBanner, nil, nil, nil, tabs)
	window.SetContent(windowContent)

	// 7. Non-blocking version check.
	go func() {
		result := update.Check("royalhouseofgeorgia", "rhg-authenticator", version)
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
