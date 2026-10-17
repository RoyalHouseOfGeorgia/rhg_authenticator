package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/royalhouseofgeorgia/rhg-authenticator/service"
)

// NewStatusBar creates a status bar widget showing registry statistics and
// the app version. info.Online indicates whether the registry was fetched from
// the remote server. info.Version is the build version (e.g. "v1.5.1"), shown
// without its "v" prefix; local builds show "Version dev".
func NewStatusBar(info service.Info) *fyne.Container {
	versionLabel := widget.NewLabel("Version " + strings.TrimPrefix(info.Version, "v"))

	if !info.Online {
		return container.NewHBox(
			widget.NewLabel("No internet"),
			layout.NewSpacer(),
			versionLabel,
		)
	}

	activeLabel := widget.NewLabel(fmt.Sprintf("Active keys: %d", info.ActiveKeys))
	recentLabel := widget.NewLabel(fmt.Sprintf("Expired (30d): %d", info.RecentlyExpired))

	return container.NewHBox(
		activeLabel,
		layout.NewSpacer(),
		recentLabel,
		layout.NewSpacer(),
		versionLabel,
	)
}
