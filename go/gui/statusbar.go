package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/core"
	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewStatusBar creates a status bar widget showing registry statistics and
// the app version. online indicates whether the registry was fetched from the
// remote server. version is the build version (e.g. "v1.5.1"), shown without
// its "v" prefix; local builds pass "dev" and show "Version dev".
func NewStatusBar(reg core.Registry, online bool, version string) *fyne.Container {
	versionLabel := widget.NewLabel("Version " + strings.TrimPrefix(version, "v"))

	if !online {
		return container.NewHBox(
			widget.NewLabel("No internet"),
			layout.NewSpacer(),
			versionLabel,
		)
	}

	today := time.Now().UTC().Format("2006-01-02")
	stats := service.ComputeRegistryStats(reg, today)

	activeLabel := widget.NewLabel(fmt.Sprintf("Active keys: %d", stats.ActiveKeys))
	recentLabel := widget.NewLabel(fmt.Sprintf("Expired (30d): %d", stats.RecentlyExpired))

	return container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		versionLabel,
	)
}
