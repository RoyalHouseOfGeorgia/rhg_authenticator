package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/gui"
	"github.com/royalhouseofgeorgia/rhg-authenticator/log"
	"github.com/royalhouseofgeorgia/rhg-authenticator/registry"
	"github.com/royalhouseofgeorgia/rhg-authenticator/update"
)

//go:embed keys/registry.json
var embeddedRegistry []byte

var version = "dev"

func main() {
	// 1. Create Fyne app and window.
	a := app.NewWithID("ge.royalhouseofgeorgia.rhg-authenticator")
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
			if err != nil || u.Scheme == "" {
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

// Ensure embed import is used (for go:embed directive).
var _ embed.FS
